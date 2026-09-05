/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-lint — C23 replacements for tools/lint shell gates.
 * Invoke: z23-lint <gate-name> [--selftest] | z23-lint <gate-name> [args...] | --list
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
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

static int fin(FILE *f, char *line, const char *path, int rc)
{
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int reg_fail(regex_t *re, int err)
{
    char msg[128];
    if (err == 0)
        return 0;
    (void)regerror(err, re, msg, sizeof msg);
    return die("z23-lint: regcomp failed: %s\n", msg);
}

static int compile_ref(regex_t *re)
{
    char pat[256];
    int n = snprintf(pat, sizeof pat, "%s%s%s%s%s%s",
                     "(^|[|;&[:space:]])(python", "3|python",
                     "2)([[:space:]]|$)|[[:space:]]python[[:space:]]+-|command -v python",
                     "3|#!/usr/bin/env pytho", "n|#!/usr/bin/pytho", "n");
    if (n < 0 || (size_t)n >= sizeof pat)
        return die("z23-lint: pattern buffer overflow\n", "");
    return reg_fail(re, regcomp(re, pat, REG_EXTENDED));
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
        if (regexec(a->re, line, 0, NULL, 0) != 0)
            continue;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        rc = note(a, "%s:%d:%s\n", path, lineno, line);
        if (rc != 0)
            break;
    }
    return fin(f, line, path, rc);
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

static int check_no_python_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    regex_t re;
    int cr = compile_ref(&re);
    if (cr) return cr;
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
        fputs("check_no_python: FAIL — Z23 must have no Python dependency\n", stderr);
        rc = replay(out);
        if (rc == 0)
            rc = 1;
    } else if (rc == 0) {
        fputs("check_no_python: clean — no Python source, shebang, or runtime path\n", stdout);
    }
    fclose(out);
    regfree(&re);
    return rc;
}

static int st_ok(int bad, const char *msg)
{
    if (bad)
        return 1;
    fputs(msg, stdout);
    return 0;
}

static int want(const char *tag, const regex_t *re, const char *s, int w)
{
    if ((regexec(re, s, 0, NULL, 0) == 0) != w) {
        fprintf(stderr, "%s selftest: want %d: %s\n", tag, w, s);
        return 1;
    }
    return 0;
}

static int check_no_python_selftest(void)
{
    regex_t re;
    int cr = compile_ref(&re);
    if (cr) return cr;
    char p1[64], p2[64], p3[64];
    if (snprintf(p1, sizeof p1, "python%s", "3 -c \"print(1)\"") >= (int)sizeof p1
        || snprintf(p2, sizeof p2, "#!" "/usr/bin/env pytho" "n%s", "3")
               >= (int)sizeof p2
        || snprintf(p3, sizeof p3, "command -v python%s", "3") >= (int)sizeof p3) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int bad = want("check_no_python", &re, "cc -std=c23 main.c", 0)
            | want("check_no_python", &re, "Never use Python.", 0)
            | want("check_no_python", &re, "No python (banned), no jq", 0)
            | want("check_no_python", &re, p1, 1)
            | want("check_no_python", &re, p2, 1)
            | want("check_no_python", &re, p3, 1);
    regfree(&re);
    return st_ok(bad, "check_no_python selftest: OK\n");
}

struct mal_acc { regex_t *hit; regex_t *excl; int hits; };

static void drop2(regex_t *a, regex_t *b) { regfree(a); regfree(b); }

static int compile_mal(regex_t *hit, regex_t *excl, const char *nm, const char *xtra)
{
    char hp[64], ep[160];
    int n = snprintf(hp, sizeof hp, "[^_]%s[[:space:]]*\\(", nm);
    if (n < 0 || (size_t)n >= sizeof hp)
        return die("z23-lint: pattern buffer overflow\n", "");
    n = snprintf(ep, sizeof ep, "zcl_%s%s|raw-alloc-ok|safe_alloc|\".*%s|LOG_|fprintf",
                 nm, xtra, nm);
    if (n < 0 || (size_t)n >= sizeof ep)
        return die("z23-lint: pattern buffer overflow\n", "");
    int err = reg_fail(hit, regcomp(hit, hp, REG_EXTENDED));
    if (err)
        return err;
    err = reg_fail(excl, regcomp(excl, ep, REG_EXTENDED));
    if (err)
        regfree(hit);
    return err;
}

static int scan_mal(const char *path, void *ctx)
{
    struct mal_acc *a = ctx;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
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
    return fin(f, line, path, rc);
}

static int walk_src(const char *dir, int hdrs,
                    int (*scan)(const char *, void *), void *ctx)
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
                rc = walk_src(path, hdrs, scan, ctx);
            else if (S_ISREG(st.st_mode) && nl >= 2 && name[nl - 2] == '.'
                     && (name[nl - 1] == 'c' || (hdrs && name[nl - 1] == 'h')))
                rc = scan(path, ctx);
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
    if (cr) return cr;
    struct mal_acc a = { .hit = &hit, .excl = &excl, .hits = 0 };
    int rc = walk_src("app", 1, scan_mal, &a);
    if (rc == 0)
        rc = walk_src("tools", 1, scan_mal, &a);
    if (rc == 0 && a.hits) {
        printf("FAIL: bare %s in app/tools code (use zcl_%s or mark // raw-alloc-ok)\n", nm, nm);
        rc = 1;
    }
    drop2(&hit, &excl);
    return rc;
}

static int check_malloc_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
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
    if (cr) return cr;
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
    return st_ok(bad, "check_malloc selftest: OK\n");
}

static int compile_pat(regex_t *re, int flags, const char *a, const char *b,
                       const char *c, const char *d)
{
    char pat[160];
    int n = snprintf(pat, sizeof pat, "%s%s%s%s", a, b, c, d);
    if (n < 0 || (size_t)n >= sizeof pat)
        return die("z23-lint: pattern buffer overflow\n", "");
    return reg_fail(re, regcomp(re, pat, flags));
}

static int pair_comp(regex_t *a, int fa, const char *a0, const char *a1,
                     const char *a2, const char *a3, regex_t *b, int fb,
                     const char *b0, const char *b1, const char *b2, const char *b3)
{
    int cr = compile_pat(a, fa, a0, a1, a2, a3);
    if (cr)
        return cr;
    cr = compile_pat(b, fb, b0, b1, b2, b3);
    if (cr)
        regfree(a);
    return cr;
}

static int miss(const char *path, FILE *out, const char *fmt)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno != ENOENT)
            return die("z23-lint: cannot stat %s\n", path);
    } else if (S_ISREG(st.st_mode))
        return 0;
    fprintf(out, fmt, path);
    return 1;
}

static int scan_re(const char *path, const regex_t *re, int *hits, int show)
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
        if (regexec(re, line, 0, NULL, 0) != 0)
            continue;
        (*hits)++;
        if (!show)
            break;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (fprintf(stdout, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    return fin(f, line, path, rc);
}

static const char *const k_np[] = {
    "tools/dev/z23_git_hook.c", "tools/dev/dev_proof_receipt.c",
    "tools/dev/dev_proof_receipt.h",
};

enum { NP_NTOK = 8 };

static int np_comp(regex_t *api, regex_t *sh)
{
    return pair_comp(api, REG_EXTENDED, "(^|[^[:alnum:]_])(sys", "tem|po",
                     "pen)[[:space:]]*\\(", "", sh, REG_EXTENDED | REG_ICASE,
                     "\"(ba", "sh|powershell|pwsh|cmd\\.exe|s",
                     "h)\"|/bin/(ba)?s", "h|[[:space:]]-c\"");
}

static int np_need(const char *path)
{
    static const char *const p[] = {
        "exec", "vp(argv[0]", "execl(binary, binary, \"dev\", \"pr", "oof\", \"ensure\"",
        "CreateProcess", "W(application", "CREATE_NO_", "WINDOW",
        "JOB_OBJECT_LIMIT_KILL_ON_JOB", "_CLOSE", "GIT_NO_LAZY", "_FETCH",
        "platform_positioned_file_open", "_beneath", "ZCL_DEV_PROOF_WIRE", "_BYTES"
    };
    char tok[NP_NTOK][80];
    int seen[NP_NTOK] = {0};
    for (int i = 0; i < NP_NTOK; i++) {
        int n = snprintf(tok[i], 80, "%s%s", p[i * 2], p[i * 2 + 1]);
        if (n < 0 || (size_t)n >= 80)
            return die("z23-lint: pattern buffer overflow\n", "");
    }
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, f) >= 0) {
        for (int i = 0; i < NP_NTOK; i++) {
            for (const char *q = line; !seen[i] && (q = strstr(q, tok[i])); q++) {
                unsigned char c = (unsigned char)q[strlen(tok[i])];
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                      || (c >= '0' && c <= '9') || c == '_'))
                    seen[i] = 1;
            }
        }
    }
    int rc = fin(f, line, path, 0);
    if (rc)
        return rc;
    for (int i = 0; i < NP_NTOK; i++) {
        if (!seen[i]) {
            fprintf(stderr, "native proof fast path: missing required token: %s\n", tok[i]);
            return 1;
        }
    }
    return 0;
}

static int np_ban(const regex_t *re, const char *err)
{
    int hits = 0, rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_np / sizeof k_np[0]; i++)
        rc = scan_re(k_np[i], re, &hits, 1);
    if (rc == 0 && hits) {
        fputs(err, stderr);
        return 1;
    }
    return rc;
}

static int check_dev_proof_native_fast_path_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    for (size_t i = 0; i < sizeof k_np / sizeof k_np[0]; i++) {
        int m = miss(k_np[i], stderr, "native proof fast path: missing %s\n");
        if (m)
            return m;
    }
    regex_t api, sh;
    int cr = np_comp(&api, &sh);
    if (cr)
        return cr;
    int rc = np_ban(&api, "native proof fast path: shell-launching C API is forbidden\n");
    if (rc == 0)
        rc = np_ban(&sh, "native proof fast path: shell executable or expansion is forbidden\n");
    if (rc == 0)
        rc = np_need(k_np[0]);
    if (rc == 0)
        fputs("native proof fast path: PASS (sealed receipt admission, no shell authority)\n", stdout);
    drop2(&api, &sh);
    return rc;
}

static int check_dev_proof_native_fast_path_selftest(void)
{
    regex_t api, sh;
    int cr = np_comp(&api, &sh);
    if (cr) return cr;
    char s1[40], s2[40], s3[24], s4[16], s5[16];
    if (snprintf(s1, sizeof s1, "rc = sys%s", "tem(\"ls\");") >= (int)sizeof s1
        || snprintf(s2, sizeof s2, "x = po%s", "pen (cmd, \"r\");") >= (int)sizeof s2
        || snprintf(s3, sizeof s3, "\"/bin/s%s", "h\"") >= (int)sizeof s3
        || snprintf(s4, sizeof s4, "\"Ba%s", "sh\"") >= (int)sizeof s4
        || snprintf(s5, sizeof s5, "\" -%s", "c\"") >= (int)sizeof s5) {
        drop2(&api, &sh);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    const char *t = "check_dev_proof_native_fast_path";
    int bad = want(t, &api, s1, 1) | want(t, &api, "int systemd_ok(void);", 0)
            | want(t, &api, s2, 1) | want(t, &sh, s3, 1) | want(t, &sh, s4, 1)
            | want(t, &sh, s5, 1) | want(t, &api, "int cmd = 1;", 0)
            | want(t, &sh, "int cmd = 1;", 0);
    drop2(&api, &sh);
    return st_ok(bad, "check_dev_proof_native_fast_path selftest: OK\n");
}

static const char *const k_bsh[] = {
    "engine/models/src/utxo.c", "engine/models/src/block.c",
    "contexts/wallet/models/src/wallet_tx.c",
};

static int bsh_comp(regex_t *hook, regex_t *plain)
{
    return pair_comp(hook, REG_EXTENDED, "ar_register_before_save",
                     "[[:space:]]*\\(", "", "", plain, REG_EXTENDED,
                     "^bool (db_wallet_key_save|db_sapling_key_save|",
                     "db_wallet_seed_save)", "[[:space:]]*\\(", "");
}

static int check_before_save_hooks_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    regex_t hook, plain;
    int cr = bsh_comp(&hook, &plain);
    if (cr) return cr;
    int rc = 0, hits;
    for (size_t i = 0; rc == 0 && i < sizeof k_bsh / sizeof k_bsh[0]; i++) {
        rc = miss(k_bsh[i], stdout, "FAIL: %s missing (model file moved/renamed)\n");
        hits = 0;
        if (rc == 0)
            rc = scan_re(k_bsh[i], &hook, &hits, 0);
        if (rc == 0 && hits == 0) {
            printf("FAIL: %s does not WIRE a before_save hook (no ar_register_before_save(...) call; a bare 'before_save' comment does not count)\n",
                   k_bsh[i]);
            rc = 1;
        }
    }
    const char *wk = "contexts/wallet/models/src/wallet_key.c";
    hits = 0;
    if (rc == 0)
        rc = miss(wk, stdout, "FAIL: %s missing (model file moved/renamed)\n");
    if (rc == 0)
        rc = scan_re(wk, &plain, &hits, 0);
    if (rc == 0 && hits) {
        fputs("FAIL: contexts/wallet/models/src/wallet_key.c re-introduced a plaintext wallet-key save — wallet_sqlite is the single writer of the secret columns\n", stdout);
        rc = 1;
    }
    if (rc == 0)
        fputs("  OK: critical models have before_save hooks\n", stdout);
    drop2(&hook, &plain);
    return rc;
}

static int check_before_save_hooks_selftest(void)
{
    regex_t hook, plain;
    int cr = bsh_comp(&hook, &plain);
    if (cr) return cr;
    const char *t = "check_before_save_hooks";
    int bad = want(t, &hook, "    ar_register_before_save(&x);", 1)
            | want(t, &hook, "/* before_save */", 0)
            | want(t, &plain, "bool db_wallet_key_save(", 1)
            | want(t, &plain, "static bool db_wallet_key_save_v2(", 0);
    drop2(&hook, &plain);
    return st_ok(bad, "check_before_save_hooks selftest: OK\n");
}

struct lg_acc {
    regex_t *hit;
    regex_t *excl;
    regex_t *prev;
    const char *skip_sub;
    const char *skip_eq;
    int hits;
};

static void drop3(regex_t *a, regex_t *b, regex_t *c)
{
    drop2(a, b);
    regfree(c);
}

static int scan_lg(const char *path, void *ctx)
{
    struct lg_acc *a = ctx;
    if ((a->skip_sub && strstr(path, a->skip_sub) != NULL)
        || (a->skip_eq && strcmp(path, a->skip_eq) == 0))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *buf[2] = { NULL, NULL };
    size_t cap[2] = { 0, 0 };
    int cur = 0, lineno = 0, rc = 0;
    ssize_t n;
    while ((n = getline(&buf[cur], &cap[cur], f)) >= 0) {
        char *line = buf[cur];
        lineno++;
        if (regexec(a->hit, line, 0, NULL, 0) == 0
            && regexec(a->excl, line, 0, NULL, 0) != 0
            && !(lineno > 1
                 && regexec(a->prev, buf[1 - cur], 0, NULL, 0) == 0)) {
            if (n > 0 && line[n - 1] == '\n')
                line[n - 1] = '\0';
            if (fprintf(stdout, "%s:%d:%s\n", path, lineno, line) < 0) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
            a->hits++;
        }
        cur = 1 - cur;
    }
    rc = fin(f, NULL, path, rc);
    free(buf[0]);
    free(buf[1]);
    return rc;
}

static int lg_got(const regex_t *hit, const regex_t *excl, const regex_t *prev,
                  const char *p, const char *s)
{
    if (regexec(hit, s, 0, NULL, 0) != 0)
        return 0;
    if (regexec(excl, s, 0, NULL, 0) == 0)
        return 0;
    if (p && regexec(prev, p, 0, NULL, 0) == 0)
        return 0;
    return 1;
}

static int lg_want(const char *tag, const regex_t *hit, const regex_t *excl,
                   const regex_t *prev, const char *p, const char *s, int w)
{
    if (lg_got(hit, excl, prev, p, s) != w) {
        fprintf(stderr, "%s selftest: want %d: %s\n", tag, w, s);
        return 1;
    }
    return 0;
}

static int pt_comp(regex_t *hit, regex_t *excl, regex_t *prev)
{
    int cr = compile_pat(hit, REG_EXTENDED, "pthread_create",
                         "[[:space:]]*\\(", "", "");
    if (cr)
        return cr;
    cr = pair_comp(excl, REG_EXTENDED, "thread_registry_spawn",
                   "|thread_registry_trampoline", "|raw-pthread-ok", "",
                   prev, REG_EXTENDED, "raw-pthread-ok", "", "", "");
    if (cr)
        regfree(hit);
    return cr;
}

static int check_pthread_create_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    regex_t hit, excl, prev;
    int cr = pt_comp(&hit, &excl, &prev);
    if (cr)
        return cr;
    struct lg_acc a = {
        .hit = &hit, .excl = &excl, .prev = &prev,
        .skip_sub = "tests/harness/include/test/",
        .skip_eq = "platform/modules/util/src/thread_registry.c",
        .hits = 0
    };
    static const char *const roots[] = { "lib", "app", "tools", "config" };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof roots / sizeof roots[0]; i++)
        rc = walk_src(roots[i], 0, scan_lg, &a);
    if (rc == 0 && a.hits) {
        fputs("FAIL: raw pthread_create in production code (use thread_registry_spawn{,_ex} or mark // raw-pthread-ok: <reason>)\n",
              stdout);
        rc = 1;
    } else if (rc == 0) {
        fputs("  OK: all pthread_create call sites accounted for\n", stdout);
    }
    drop3(&hit, &excl, &prev);
    return rc;
}

static int check_pthread_create_selftest(void)
{
    regex_t hit, excl, prev;
    int cr = pt_comp(&hit, &excl, &prev);
    if (cr)
        return cr;
    const char *t = "check_pthread_create";
    int bad = lg_want(t, &hit, &excl, &prev, NULL,
                      "    pthread_crea" "te(&t, 0, f, 0);", 1)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    thread_registry_spawn(...)", 0)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    pthread_crea" "te(&t, 0, f, 0); // raw-pthread-ok: x", 0)
            | lg_want(t, &hit, &excl, &prev, "// raw-pthread-ok: startup",
                      "pthread_crea" "te(", 0)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "my_pthread_create_wrapper(", 0);
    drop3(&hit, &excl, &prev);
    return st_ok(bad, "check_pthread_create selftest: OK\n");
}

static int ser_comp(regex_t *hit, regex_t *excl, regex_t *prev)
{
    int cr = compile_pat(hit, REG_EXTENDED, "return -1;", "", "", "");
    if (cr)
        return cr;
    cr = pair_comp(excl, REG_EXTENDED, "LOG_ERR|LOG_FAIL|LOG_RETURN|log_json",
                   "|(//|/\\*) raw-return-ok:[A-Za-z][A-Za-z0-9_-]+", "", "",
                   prev, REG_EXTENDED, "LOG_ERR|LOG_FAIL|LOG_RETURN|",
                   "log_json.*error", "", "");
    if (cr)
        regfree(hit);
    return cr;
}

static int check_silent_error_returns_run(int argc, char **argv)
{
    if (argc < 4)
        return die("usage: check_silent_error_returns.sh <scan-dir> <fail-label> <ok-label> <fix-hint>\n",
                   "");
    regex_t hit, excl, prev;
    int cr = ser_comp(&hit, &excl, &prev);
    if (cr)
        return cr;
    struct lg_acc a = {
        .hit = &hit, .excl = &excl, .prev = &prev,
        .skip_sub = NULL, .skip_eq = NULL, .hits = 0
    };
    int rc = walk_src(argv[0], 0, scan_lg, &a);
    if (rc == 0 && a.hits) {
        printf("FAIL: silent error returns found in %s (%s)\n", argv[1], argv[3]);
        rc = 1;
    } else if (rc == 0) {
        printf("  OK: all %s error returns logged\n", argv[2]);
    }
    drop3(&hit, &excl, &prev);
    return rc;
}

static int check_silent_error_returns_selftest(void)
{
    regex_t hit, excl, prev;
    int cr = ser_comp(&hit, &excl, &prev);
    if (cr)
        return cr;
    const char *t = "check_silent_error_returns";
    int bad = lg_want(t, &hit, &excl, &prev, NULL, "    return -1;", 1)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    LOG_ERR(\"x\"); return -1;", 0)
            | lg_want(t, &hit, &excl, &prev, "    LOG_FAIL(\"bad\");",
                      "    return -1;", 0)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    return -1; // raw-return-ok:reason_1", 0)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    return -1; // raw-return-ok:", 1)
            | lg_want(t, &hit, &excl, &prev, "    log_json(\"error\", ...)",
                      "    return -1;", 0)
            | lg_want(t, &hit, &excl, &prev, "    log_json(\"info\", ...)",
                      "    return -1;", 1);
    drop3(&hit, &excl, &prev);
    return st_ok(bad, "check_silent_error_returns selftest: OK\n");
}

static int va_comp(regex_t *hit, regex_t *excl, regex_t *prev)
{
    int cr = compile_pat(hit, REG_EXTENDED, ",[[:space:]]*##", "[[:space:]]*",
                         "__VA", "_ARGS__");
    if (cr) return cr;
    cr = pair_comp(excl, REG_EXTENDED, "gnu-va-args-ok", "", "", "",
                   prev, REG_EXTENDED, "gnu-va-args-ok", "", "", "");
    if (cr) regfree(hit);
    return cr;
}

static int check_no_gnu_va_args_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    regex_t hit, excl, prev;
    int cr = va_comp(&hit, &excl, &prev);
    if (cr) return cr;
    struct lg_acc a = { .hit = &hit, .excl = &excl, .prev = &prev, .hits = 0 };
    static const char *const roots[] = {
        "app", "config", "core", "lib", "domain", "engine/application",
        "platform/adapters", "platform/ports", "src", "tools"
    };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof roots / sizeof roots[0]; i++)
        rc = walk_src(roots[i], 1, scan_lg, &a);
    if (rc == 0 && a.hits) {
        fputs("FAIL: GNU ', ##" "__VA_ARGS__' extension in C23 source.\n"
              "      Use '__VA_OPT__(,) __VA_ARGS__' instead, or mark the line\n"
              "      // gnu-va-args-ok: <reason>\n", stdout);
        rc = 1;
    } else if (rc == 0) {
        fputs("  OK: no GNU comma-swallowing __VA_ARGS__ (C23 __VA_OPT__ everywhere)\n",
              stdout);
    }
    drop3(&hit, &excl, &prev);
    return rc;
}

static int check_no_gnu_va_args_selftest(void)
{
    regex_t hit, excl, prev;
    int cr = va_comp(&hit, &excl, &prev);
    if (cr) return cr;
    const char *t = "check_no_gnu_va_args";
    char h[72], m[88];
    if (snprintf(h, sizeof h, "    fprintf(stderr, fmt, ##%s", "__VA_ARGS__);")
            >= (int)sizeof h
        || snprintf(m, sizeof m, "%s // gnu-va-args-ok: legacy", h) >= (int)sizeof m) {
        drop3(&hit, &excl, &prev);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int bad = lg_want(t, &hit, &excl, &prev, NULL, h, 1)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    LOG_ERR(fmt __VA_OPT__(,) __VA_ARGS__);", 0)
            | lg_want(t, &hit, &excl, &prev, NULL, m, 0)
            | lg_want(t, &hit, &excl, &prev, "// gnu-va-args-ok: legacy", h, 0)
            | lg_want(t, &hit, &excl, &prev, NULL, "    x = a ## b;", 0);
    drop3(&hit, &excl, &prev);
    return st_ok(bad, "check_no_gnu_va_args selftest: OK\n");
}

enum { SI_MAX = 64, SI_NAME = 96, SI_OUT = 8192 };
struct si_rec { int rank, order; char name[SI_NAME]; };
struct si_acc { struct si_rec rec[SI_MAX]; int n, rc; char err[256]; };
static const char k_si_src[] = "engine/composition/src/boot.c";
static const char k_si_gold[] = "tools/lint/sysinit_ordering_golden.txt";

static int si_rank_of(const char *s)
{
    static const char *const nm[] = {
        "INIT", "DATADIR_LOCKED", "CRYPTO_READY", "DB_OPEN", "WALLET_LOADED",
        "BLOCK_INDEX_LOADED", "CHAIN_TIP_RESOLVED", "NETWORK_READY",
        "SERVICES_RUNNING", "READY", "SHUTDOWN_REQUESTED", "SHUTDOWN_COMPLETE"
    };
    for (int i = 0; i < 12; i++)
        if (strcmp(nm[i], s) == 0) return i;
    return -1;
}

static int si_cmp(const void *a, const void *b)
{
    const struct si_rec *x = a, *y = b;
    if (x->rank != y->rank) return (x->rank > y->rank) - (x->rank < y->rank);
    if (x->order != y->order) return (x->order > y->order) - (x->order < y->order);
    return strcmp(x->name, y->name);
}

static int si_cap(const regex_t *re, const char *s, char *dst, size_t cap)
{
    regmatch_t m[2];
    if (regexec(re, s, 2, m, 0) != 0 || m[1].rm_so < 0) return 0;
    size_t n = (size_t)(m[1].rm_eo - m[1].rm_so);
    if (n >= cap) n = cap - 1;
    memcpy(dst, s + m[1].rm_so, n);
    dst[n] = '\0';
    return 1;
}

static int si_comp(regex_t *stg, regex_t *ord, regex_t *nam)
{
    int cr = compile_pat(stg, REG_EXTENDED,
                         "\\.stage[[:space:]]*=[[:space:]]*BOOT_STAGE_([A-Z_]*)",
                         "", "", "");
    if (cr) return cr;
    cr = pair_comp(ord, REG_EXTENDED,
                   "\\.order[[:space:]]*=[[:space:]]*(-?[0-9]*)", "", "", "",
                   nam, REG_EXTENDED,
                   "\\.name[[:space:]]*=[[:space:]]*\"([^\"]*)\"", "", "", "");
    if (cr) regfree(stg);
    return cr;
}

static int si_die(struct si_acc *a, const char *fmt, const char *arg)
{
    snprintf(a->err, sizeof a->err, fmt, arg);
    a->rc = 2;
    return 2;
}

static int si_feed(struct si_acc *a, const regex_t *stg, const regex_t *ord,
                   const regex_t *nam, const char *line)
{
    char stage[32], order[16], name[SI_NAME];
    if (!si_cap(stg, line, stage, sizeof stage) || !stage[0]) return 0;
    if (!si_cap(ord, line, order, sizeof order) || !order[0]
        || !si_cap(nam, line, name, sizeof name) || !name[0])
        return si_die(a, "check_sysinit_ordering: FATAL — record line missing .order/.name: %s\n",
                      line);
    int rank = si_rank_of(stage);
    if (rank < 0)
        return si_die(a, "check_sysinit_ordering: FATAL — unknown BOOT_STAGE_%s (update STAGE_RANK)\n",
                      stage);
    if (a->n >= SI_MAX)
        return si_die(a, "check_sysinit_ordering: FATAL — too many boundary records\n", "");
    a->rec[a->n].rank = rank;
    a->rec[a->n].order = (int)strtol(order, NULL, 10);
    memcpy(a->rec[a->n].name, name, sizeof name);
    a->n++;
    return 0;
}

static int si_finish(struct si_acc *a, char *out, size_t outsz, int *nrec)
{
    if (a->rc) return 2;
    if (a->n == 0)
        return si_die(a, "check_sysinit_ordering: FATAL — no boundary records found in %s\n",
                      k_si_src);
    qsort(a->rec, (size_t)a->n, sizeof a->rec[0], si_cmp);
    size_t used = 0;
    for (int i = 0; i < a->n; i++) {
        int k = snprintf(out + used, outsz - used, "%02d %06d %s\n",
                         a->rec[i].rank, a->rec[i].order, a->rec[i].name);
        if (k < 0 || (size_t)k >= outsz - used)
            return si_die(a, "z23-lint: derived buffer overflow\n", "");
        used += (size_t)k;
    }
    if (nrec) *nrec = a->n;
    return 0;
}

static int si_from_buf(const char *src, char *out, size_t outsz, int *nrec,
                       char *err, size_t errsz)
{
    regex_t stg, ord, nam;
    int cr = si_comp(&stg, &ord, &nam);
    if (cr) return cr;
    struct si_acc a = { 0 };
    char buf[1024];
    if (snprintf(buf, sizeof buf, "%s", src) >= (int)sizeof buf) {
        drop3(&stg, &ord, &nam);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    for (char *p = buf, *nl; p; p = nl ? nl + 1 : NULL) {
        nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        if (si_feed(&a, &stg, &ord, &nam, p)) break;
        if (!nl) break;
    }
    drop3(&stg, &ord, &nam);
    int rc = si_finish(&a, out, outsz, nrec);
    if (rc) snprintf(err, errsz, "%s", a.err);
    return rc;
}

static int si_load(struct si_acc *a)
{
    regex_t stg, ord, nam;
    int cr = si_comp(&stg, &ord, &nam);
    if (cr) return cr;
    FILE *f = fopen(k_si_src, "r");
    if (!f) {
        drop3(&stg, &ord, &nam);
        return die("z23-lint: cannot open %s\n", k_si_src);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (si_feed(a, &stg, &ord, &nam, line)) break;
    }
    int fr = fin(f, line, k_si_src, 0);
    drop3(&stg, &ord, &nam);
    if (a->rc) { fputs(a->err, stderr); return 2; }
    return fr;
}

static int check_sysinit_ordering_run(int argc, char **argv)
{
    struct si_acc a = { 0 };
    int rc = si_load(&a);
    if (rc) return rc;
    char der[SI_OUT], gold[SI_OUT];
    int nrec = 0;
    if (si_finish(&a, der, sizeof der, &nrec)) { fputs(a.err, stderr); return 2; }
    if (argc >= 1 && strcmp(argv[0], "--update") == 0) {
        FILE *g = fopen(k_si_gold, "w");
        if (!g) return die("z23-lint: cannot open %s\n", k_si_gold);
        size_t dn = strlen(der);
        rc = fwrite(der, 1, dn, g) != dn;
        if (fclose(g) != 0 && rc == 0) return die("z23-lint: fclose failed: %s\n", k_si_gold);
        if (rc) return die("z23-lint: write failed\n", "");
        printf("[check_sysinit_ordering] golden updated (%d records)\n", nrec);
        return 0;
    }
    FILE *g = fopen(k_si_gold, "r");
    if (!g) {
        fputs("check_sysinit_ordering: FATAL — missing golden tools/lint/sysinit_ordering_golden.txt (run --update)\n",
              stderr);
        return 2;
    }
    size_t used = fread(gold, 1, sizeof gold - 1, g);
    rc = ferror(g) ? die("z23-lint: read failed: %s\n", k_si_gold) : 0;
    if (rc == 0 && used == sizeof gold - 1 && !feof(g))
        rc = die("z23-lint: file too large: %s\n", k_si_gold);
    gold[used] = '\0';
    if (fclose(g) != 0 && rc == 0) return die("z23-lint: fclose failed: %s\n", k_si_gold);
    if (rc) return rc;
    if (strcmp(gold, der) != 0) {
        fprintf(stderr, "--- %s\n%s+++ derived\n%s", k_si_gold, gold, der);
        fputs("[check_sysinit_ordering] FAIL — sysinit boundary order drifted from the golden.\n"
              "[check_sysinit_ordering] If intentional: tools/lint/check_sysinit_ordering.sh --update\n",
              stderr);
        return 1;
    }
    int nl = 0;
    for (size_t i = 0; i < used; i++) if (gold[i] == '\n') nl++;
    printf("[check_sysinit_ordering] OK — %d boundary records match the golden\n", nl);
    return 0;
}

static int si_want(const char *src, int want_rc, const char *need)
{
    char out[SI_OUT], err[256];
    int n = 0, rc = si_from_buf(src, out, sizeof out, &n, err, sizeof err);
    int bad = rc != want_rc || (want_rc ? strstr(err, need) == NULL : strcmp(out, need) != 0);
    if (bad)
        fprintf(stderr, "check_sysinit_ordering selftest: want rc %d got %d\n", want_rc, rc);
    return bad;
}

static int check_sysinit_ordering_selftest(void)
{
    const char *fwd =
        "{ .stage = BOOT_STAGE_WALLET_LOADED, .order = 10, .name = \"wallet_loaded\" }\n"
        "{ .stage = BOOT_STAGE_BLOCK_INDEX_LOADED, .order = 10, .name = \"block_index_loaded\" }\n";
    const char *rev =
        "{ .stage = BOOT_STAGE_BLOCK_INDEX_LOADED, .order = 10, .name = \"block_index_loaded\" }\n"
        "{ .stage = BOOT_STAGE_WALLET_LOADED, .order = 10, .name = \"wallet_loaded\" }\n";
    const char *exp = "04 000010 wallet_loaded\n05 000010 block_index_loaded\n";
    int bad = si_want(fwd, 0, exp) | si_want(rev, 0, exp)
            | si_want("{ .stage = BOOT_STAGE_NOPE, .order = 1, .name = \"x\" }\n", 2,
                      "unknown BOOT_STAGE_NOPE (update STAGE_RANK)")
            | si_want("{ .stage=BOOT_STAGE_INIT, .name=\"x\" }\n", 2,
                      "record line missing .order/.name:")
            | si_want("", 2, "no boundary records found in engine/composition/src/boot.c");
    return st_ok(bad, "check_sysinit_ordering selftest: OK\n");
}

/* C scan_exclusions/repo_shape/gate_lib bits. Non-parity: no ZCL_GATE_SCAN_LOG. */
enum { RS_MAX = 256, RS_NAME = 64, RS_PATH = 192, RS_AUTH = 32, RS_SHAPE = 16,
       CLK_MATCH = 65536 };
static const char k_planted[] = "tools/lint/fixtures/planted";
static const char k_clock_script[] =
    "tools/lint/check_no_raw_clock_outside_platform.sh";
static regex_t g_excl_re;
static int g_excl_ok, g_n_ctx, g_n_shapes, g_n_libs, g_n_mods, g_n_auth, g_rs_ready;
static char g_ctx[RS_MAX][RS_NAME], g_shapes[RS_SHAPE][RS_NAME];
static char g_libs[RS_MAX][RS_NAME], g_mods[RS_MAX][RS_PATH], g_auth[RS_AUTH][RS_PATH];
static const char *const k_domain[] = {
    "contexts/wallet/domain", "platform/domain/encoding"
};

static int ovf(int n, size_t cap)
{ return (n < 0 || (size_t)n >= cap) ? die("z23-lint: derived buffer overflow\n", "") : 0; }
static int rs_ovf(void) { return die("z23-lint: repo-shape overflow\n", ""); }
static const char *rs_root(void)
{ const char *e = getenv("ZCL_REPO_SHAPE_ROOT"); return (e && e[0]) ? e : "."; }
static int lint_prod_scan(void)
{ const char *e = getenv("ZCL_LINT_PRODUCTION_SCAN"); return e && strcmp(e, "1") == 0; }

static int excl_ensure(void)
{
    if (g_excl_ok) return 0;
    char pat[256];
    int n = snprintf(pat, sizeof pat, "%s|%s%s%s%s%s",
                     "(^|/)_[^/]*fixture[^/]*\\.[ch]$", "(^|/)", k_planted,
                     "/|(^|/)build/|(^|/)vendor/|(^|/)\\.claude/",
                     "|(^|/)test-tmp/", "");
    if (ovf(n, sizeof pat)) return 2;
    int err = reg_fail(&g_excl_re, regcomp(&g_excl_re, pat, REG_EXTENDED));
    return err ? err : (g_excl_ok = 1, 0);
}

static int lint_path_is_excluded(const char *path)
{ return lint_prod_scan() && !excl_ensure() && regexec(&g_excl_re, path, 0, NULL, 0) == 0; }

static int lint_filter_excluded(const char *in, char *out, size_t cap)
{
    if (!lint_prod_scan())
        return ovf(snprintf(out, cap, "%s", in), cap);
    if (excl_ensure()) return 2;
    size_t used = 0;
    out[0] = '\0';
    for (const char *p = in; *p; ) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[4096];
        if (n >= sizeof line) return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        if (regexec(&g_excl_re, line, 0, NULL, 0) != 0) {
            int k = snprintf(out + used, cap - used, "%s%s", line, nl ? "\n" : "");
            if (ovf(k, cap - used)) return 2;
            used += (size_t)k;
        }
        p = nl ? nl + 1 : p + n;
        if (!nl) break;
    }
    return 0;
}

static int lint_annotate_stray(const char *path, FILE *out)
{
    char cmd[4096];
    if (ovf(snprintf(cmd, sizeof cmd, "git ls-files --error-unmatch -- %s", path),
            sizeof cmd))
        return 2;
    FILE *p = popen(cmd, "r");
    if (!p) return die("z23-lint: popen failed (%s)\n", cmd);
    char *buf = NULL;
    size_t cap = 0;
    while (getline(&buf, &cap, p) >= 0) { }
    free(buf);
    int st = pclose(p);
    if (st == 0)
        return fputs(path, out) < 0 ? die("z23-lint: write failed\n", "") : 0;
    return fprintf(out, "%s [untracked stray file -- not a code violation; "
                   "likely left by a crashed agent/worktree, delete it]", path) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int gate_require_scanned(int count, int floor, const char *name,
                                const char *hint)
{
    if (count >= floor) return 0;
    fprintf(stderr, "%s: FATAL — scan set is '%d' (< floor %d).\n", name, count, floor);
    fputs("  The scan producer (find/glob/grep) returned too little; a\n"
          "  scanned dir/file was likely renamed, moved, or deleted.\n"
          "  Refusing to report 'clean' off a hollow (empty) scan.\n", stderr);
    if (hint && hint[0]) fprintf(stderr, "  %s\n", hint);
    return 2;
}

static int gate_count_and_report(const char *matches, int *out_count)
{
    *out_count = 0;
    if (!matches) return 0;
    int any = 0;
    for (const char *s = matches; *s; s++)
        if (!isspace((unsigned char)*s)) { any = 1; break; }
    if (!any) return 0;
    for (const char *p = matches; *p; ) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n > 0) {
            (*out_count)++;
            if (fwrite(p, 1, n, stderr) != n || fputc('\n', stderr) == EOF)
                return die("z23-lint: write failed\n", "");
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

static int rs_continues(const char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '
                 || s[n - 1] == '\t'))
        n--;
    return n && s[n - 1] == '\\';
}

static int rs_emit(char *line, char dst[][RS_NAME], int max, int *n)
{
    char *hash = strchr(line, '#');
    if (hash) *hash = '\0';
    for (char *q = line; *q; q++) if (*q == '\\') *q = ' ';
    *n = 0;
    for (char *p = line; *p; ) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        char *s = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        char save = *p;
        *p = '\0';
        if (*n >= max || strlen(s) >= RS_NAME) return rs_ovf();
        memcpy(dst[*n], s, strlen(s) + 1);
        (*n)++;
        *p = save;
        if (save) p++;
    }
    return 0;
}

static int rs_make_list(const char *variable, char dst[][RS_NAME], int max, int *n)
{
    const char *mk = getenv("ZCL_REPO_SHAPE_MAKEFILE");
    char path[4096];
    if (!mk || !mk[0]) {
        if (ovf(snprintf(path, sizeof path, "%s/Makefile", rs_root()), sizeof path))
            return 2;
        mk = path;
    }
    FILE *f = fopen(mk, "r");
    if (!f) return die("z23-lint: cannot open %s\n", mk);
    char *line = NULL, assembled[8192];
    size_t cap = 0, alen = strlen(variable);
    int found = 0, rc = 0;
    assembled[0] = '\0';
    while (getline(&line, &cap, f) >= 0) {
        if (!found) {
            if (strncmp(line, variable, alen) != 0) continue;
            const char *p = line + alen;
            while (*p == ' ' || *p == '\t') p++;
            if (*p != '=') continue;
            found = 1;
            if (ovf(snprintf(assembled, sizeof assembled, "%s", p + 1), sizeof assembled)) {
                rc = 2; break;
            }
            if (!rs_continues(line)) break;
            continue;
        }
        size_t used = strlen(assembled);
        int k = snprintf(assembled + used, sizeof assembled - used, " %s", line);
        if (ovf(k, sizeof assembled - used)) { rc = 2; break; }
        if (!rs_continues(line)) break;
    }
    if (rc == 0) rc = found ? rs_emit(assembled, dst, max, n) : (*n = 0, 0);
    return fin(f, line, mk, rc);
}

static int rs_cmp_name(const void *a, const void *b) { return strcmp(a, b); }

static int rs_uniq(void *arr, int n, size_t stride)
{
    if (n <= 1) return n;
    qsort(arr, (size_t)n, stride, rs_cmp_name);
    int w = 1;
    char *base = arr;
    for (int i = 1; i < n; i++) {
        if (strcmp(base + (size_t)i * stride, base + (size_t)(w - 1) * stride) != 0) {
            if (w != i)
                memcpy(base + (size_t)w * stride, base + (size_t)i * stride, stride);
            w++;
        }
    }
    return w;
}

static const char *rs_env_or(const char *env, char *buf, size_t cap, const char *fmt)
{
    const char *e = getenv(env);
    if (e && e[0]) return e;
    return ovf(snprintf(buf, cap, fmt, rs_root()), cap) ? NULL : buf;
}

static int rs_lib_modules(void)
{
    char path[4096];
    const char *md = rs_env_or("ZCL_REPO_SHAPE_MODULE_DEF", path, sizeof path,
                               "%s/engine/composition/lib_module_order.def");
    if (!md) return 2;
    FILE *f = fopen(md, "r");
    if (!f) return die("z23-lint: cannot open %s\n", md);
    char *line = NULL;
    size_t cap = 0;
    g_n_libs = 0;
    int rc = 0;
    while (getline(&line, &cap, f) >= 0) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "LIB_MODULE(\"", 12) != 0) continue;
        p += 12;
        char *e = p;
        while ((*e >= 'A' && *e <= 'Z') || (*e >= 'a' && *e <= 'z')
               || (*e >= '0' && *e <= '9') || *e == '_')
            e++;
        if (*e != '"' || e[1] != ')' ) continue;
        size_t n = (size_t)(e - p);
        if (g_n_libs >= RS_MAX || n >= RS_NAME) { rc = rs_ovf(); break; }
        memcpy(g_libs[g_n_libs], p, n);
        g_libs[g_n_libs][n] = '\0';
        g_n_libs++;
    }
    rc = fin(f, line, md, rc);
    if (rc) return rc;
    g_n_libs = rs_uniq(g_libs, g_n_libs, RS_NAME);
    return 0;
}

static int rs_is_module_dir(const char *rel)
{
    const char *slash = strrchr(rel, '/');
    if (!slash || slash == rel || slash[1] == '\0') return 0;
    if (slash >= rel + 8 && strncmp(slash - 8, "/modules", 8) == 0) return 1;
    return strncmp(rel, "modules/", 8) == 0 && strchr(rel + 8, '/') == NULL;
}

static int rs_mod_walk(const char *dir, int depth)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return (errno == ENOENT || errno == EACCES) ? 0
            : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") && strcmp(name, "..")) {
            char path[4096];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (ovf(k, sizeof path)) rc = 2;
            else if (lstat(path, &st) != 0)
                rc = (errno == ENOENT || errno == EACCES) ? 0
                    : die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode)) {
                int nd = depth + 1;
                if (nd >= 2 && nd <= 4) {
                    const char *root = rs_root();
                    size_t rl = strlen(root);
                    const char *rel = (strncmp(path, root, rl) == 0 && path[rl] == '/')
                        ? path + rl + 1 : path;
                    if (rs_is_module_dir(rel)) {
                        if (g_n_mods >= RS_MAX || strlen(rel) >= RS_PATH) rc = rs_ovf();
                        else { memcpy(g_mods[g_n_mods], rel, strlen(rel) + 1); g_n_mods++; }
                    }
                }
                if (rc == 0 && nd < 4) rc = rs_mod_walk(path, nd);
            }
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int rs_isdir(const char *rel)
{
    char path[4096];
    struct stat st;
    if (ovf(snprintf(path, sizeof path, "%s/%s", rs_root(), rel), sizeof path))
        return 0;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int rs_put(char out[][RS_PATH], int max, int *n, const char *base,
                  const char *leaf)
{
    char path[RS_PATH];
    int k = (leaf && leaf[0]) ? snprintf(path, sizeof path, "%s/%s", base, leaf)
                              : snprintf(path, sizeof path, "%s", base);
    if (ovf(k, sizeof path)) return 2;
    if (!rs_isdir(path)) return 0;
    if (*n >= max) return rs_ovf();
    memcpy(out[*n], path, strlen(path) + 1);
    (*n)++;
    return 0;
}

static int rs_init(void)
{
    if (g_rs_ready) return 0;
    char mk[4096], md[4096];
    const char *mkp = rs_env_or("ZCL_REPO_SHAPE_MAKEFILE", mk, sizeof mk, "%s/Makefile");
    const char *mdp = rs_env_or("ZCL_REPO_SHAPE_MODULE_DEF", md, sizeof md,
                                "%s/engine/composition/lib_module_order.def");
    if (!mkp || !mdp) return 2;
    FILE *fm = fopen(mkp, "r"), *fd = fopen(mdp, "r");
    if (!fm || !fd) {
        if (fm) fclose(fm);
        if (fd) fclose(fd);
        fputs("repo-shape: FATAL — architecture declarations are unreadable\n", stderr);
        return 2;
    }
    fclose(fm); fclose(fd);
    int rc = rs_make_list("PRODUCT_CONTEXTS", g_ctx, RS_MAX, &g_n_ctx);
    if (rc == 0) rc = rs_make_list("APP_DIRS", g_shapes, RS_SHAPE, &g_n_shapes);
    if (rc == 0) rc = rs_lib_modules();
    if (rc == 0)
        rc = gate_require_scanned(g_n_ctx, 1, "repo-shape",
                                  "PRODUCT_CONTEXTS parse came back empty");
    if (rc == 0)
        rc = gate_require_scanned(g_n_shapes, 1, "repo-shape",
                                  "APP_DIRS parse came back empty");
    if (rc == 0)
        rc = gate_require_scanned(g_n_libs, 1, "repo-shape",
                                  "module declaration parse came back empty");
    g_n_mods = 0;
    static const char *const auth[] = {
        "core", "engine", "cognition", "platform", "contexts"
    };
    for (size_t i = 0; rc == 0 && i < sizeof auth / sizeof auth[0]; i++) {
        char start[4096];
        if (ovf(snprintf(start, sizeof start, "%s/%s", rs_root(), auth[i]), sizeof start))
            return 2;
        rc = rs_mod_walk(start, 0);
    }
    if (rc) return rc;
    g_n_mods = rs_uniq(g_mods, g_n_mods, RS_PATH);
    rc = gate_require_scanned(g_n_mods, g_n_libs, "repo-shape",
                              "physical module directory set is incomplete");
    if (rc) return rc;
    memcpy(g_auth[0], "engine", 7);
    memcpy(g_auth[1], "cognition", 10);
    g_n_auth = 2;
    for (int i = 0; i < g_n_ctx; i++) {
        if (g_n_auth >= RS_AUTH) return rs_ovf();
        if (ovf(snprintf(g_auth[g_n_auth], RS_PATH, "contexts/%s", g_ctx[i]), RS_PATH))
            return 2;
        g_n_auth++;
    }
    g_rs_ready = 1;
    return 0;
}

static int repo_shape_dirs(const char *family, const char *leaf,
                           char out[][RS_PATH], int max, int *n)
{
    int rc = rs_init();
    if (rc) return rc;
    *n = 0;
    if (strcmp(family, "app") == 0) {
        for (int a = 0; rc == 0 && a < g_n_auth; a++)
            for (int s = 0; rc == 0 && s < g_n_shapes; s++) {
                char base[RS_PATH];
                if (ovf(snprintf(base, sizeof base, "%s/%s", g_auth[a], g_shapes[s]),
                        sizeof base))
                    return 2;
                rc = rs_put(out, max, n, base, leaf);
            }
        return rc;
    }
    if (strcmp(family, "lib") == 0) {
        for (int i = 0; rc == 0 && i < g_n_mods; i++)
            rc = rs_put(out, max, n, g_mods[i], leaf);
        return rc;
    }
    if (strcmp(family, "domain") == 0) {
        for (size_t i = 0; rc == 0 && i < sizeof k_domain / sizeof k_domain[0]; i++)
            rc = rs_put(out, max, n, k_domain[i], leaf);
        return rc;
    }
    fprintf(stderr, "repo_shape_dirs: FATAL — unknown family '%s'\n", family);
    return 2;
}

static int repo_shape_room_dirs(const char *shape, char out[][RS_PATH], int max,
                                int *n)
{
    int rc = rs_init();
    if (rc) return rc;
    *n = 0;
    for (int i = 0; rc == 0 && i < g_n_auth; i++)
        rc = rs_put(out, max, n, g_auth[i], shape);
    if (rc) return rc;
    if (*n == 0) {
        fprintf(stderr, "repo_shape_room_dirs: FATAL — no '%s' room exists\n", shape);
        return 2;
    }
    return 0;
}

struct clock_acc { regex_t *re; char *buf; size_t cap, used; };

static int clock_comp(regex_t *re)
{
    char pat[256];
    int n = snprintf(pat, sizeof pat, "%s%s%s%s",
                     "(^|[^[:alnum:]_])clock" "_gettime[[:space:]]*\\(|",
                     "(^|[^[:alnum:]_])get" "timeofday[[:space:]]*\\(|",
                     "(^|[^[:alnum:]_])ti" "me[[:space:]]*\\([[:space:]]*NULL[[:space:]]*\\)|",
                     "(^|[^[:alnum:]_])get" "random[[:space:]]*\\(");
    return ovf(n, sizeof pat) ? 2 : reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int clock_keep(const char *path, const char *text)
{
    size_t sl = sizeof k_clock_script - 1;
    if (lint_path_is_excluded(path)
        || strncmp(path, "platform/modules/platform/", 26) == 0
        || (strncmp(path, k_clock_script, sl) == 0 && (path[sl] == '\0' || path[sl] == ':'))
        || strstr(text, "// platform-ok") != NULL)
        return 0;
    return 1;
}

static int scan_clock(const char *path, void *ctx)
{
    struct clock_acc *a = ctx;
    if (!clock_keep(path, "")) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->re, line, 0, NULL, 0) != 0) continue;
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (!clock_keep(path, line)) continue;
        int k = snprintf(a->buf + a->used, a->cap - a->used, "%s:%d:%s\n",
                         path, lineno, line);
        if (ovf(k, a->cap - a->used)) { rc = 2; break; }
        a->used += (size_t)k;
    }
    return fin(f, line, path, rc);
}

static const char *clock_mode(void)
{ const char *m = getenv("ZCL_LINT_MODE"); return (m && m[0]) ? m : "FAIL"; }
static int clock_grade(int v, const char *mode)
{ return (v > 0 && strcmp(mode, "FAIL") == 0) ? 1 : 0; }

static int clock_summary(int v, const char *mode)
{
    return (printf("[check_no_raw_clock_outside_platform] %d violation(s) found (mode: %s)\n",
                   v, mode) < 0
            || puts("[check_no_raw_clock_outside_platform] ratchet now FAIL -- no new raw clock calls allowed") < 0
            || puts("[check_no_raw_clock_outside_platform] use platform.clock/platform.rng or add // platform-ok for a documented exception") < 0)
               ? die("z23-lint: write failed\n", "") : 0;
}

static int clock_walk(const char *const *roots, size_t nr, void *ctx)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < nr; i++) rc = walk_src(roots[i], 1, scan_clock, ctx);
    return rc;
}

static int check_no_raw_clock_outside_platform_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *mode = clock_mode();
    int rc = rs_init();
    if (rc) return rc;
    regex_t re;
    rc = clock_comp(&re);
    if (rc) return rc;
    char matches[CLK_MATCH];
    matches[0] = '\0';
    struct clock_acc a = { .re = &re, .buf = matches, .cap = sizeof matches, .used = 0 };
    static const char *const prefix[] = {
        "tools", "engine/composition", "engine/application",
        "platform/adapters", "platform/ports"
    };
    static const char *const suffix[] = {
        "core/consensus", "core/params", "core/math", "core/chainparams"
    };
    rc = clock_walk(prefix, sizeof prefix / sizeof prefix[0], &a);
    char dirs[RS_MAX][RS_PATH];
    int n = 0;
    if (rc == 0) rc = repo_shape_dirs("app", "", dirs, RS_MAX, &n);
    for (int i = 0; rc == 0 && i < n; i++) rc = walk_src(dirs[i], 1, scan_clock, &a);
    n = 0;
    if (rc == 0) rc = repo_shape_dirs("lib", "", dirs, RS_MAX, &n);
    for (int i = 0; rc == 0 && i < n; i++) rc = walk_src(dirs[i], 1, scan_clock, &a);
    if (rc == 0) rc = clock_walk(k_domain, sizeof k_domain / sizeof k_domain[0], &a);
    if (rc == 0) rc = clock_walk(suffix, sizeof suffix / sizeof suffix[0], &a);
    int violations = 0;
    if (rc == 0) rc = gate_count_and_report(matches, &violations);
    if (rc == 0) rc = clock_summary(violations, mode);
    regfree(&re);
    return rc ? rc : clock_grade(violations, mode);
}

static int clock_case(const regex_t *re, const char *path, const char *text,
                      int want_n, int want_rc, const char *mode)
{
    char buf[256] = {0};
    int n = 0;
    if (regexec(re, text, 0, NULL, 0) == 0 && clock_keep(path, text)
        && ovf(snprintf(buf, sizeof buf, "%s:%d:%s\n", path, 1, text), sizeof buf))
        return 1;
    if (gate_count_and_report(buf, &n)) return 1;
    return n != want_n || clock_grade(n, mode) != want_rc;
}

static int check_no_raw_clock_outside_platform_selftest(void)
{
    regex_t re;
    int cr = clock_comp(&re);
    if (cr) return cr;
    char hit[80], marked[96];
    if (snprintf(hit, sizeof hit, "    clock" "_gettime(CLOCK_REALTIME, &ts);")
            >= (int)sizeof hit
        || snprintf(marked, sizeof marked, "%s // platform-ok", hit) >= (int)sizeof marked) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    const char *t = "check_no_raw_clock_outside_platform";
    int bad = want(t, &re, "int x = 1;", 0) | want(t, &re, hit, 1)
            | want(t, &re, "my_clock" "_gettime(&ts);", 0)
            | clock_case(&re, "tools/lint/foo.c", "int x = 1;", 0, 0, "FAIL")
            | clock_case(&re, "tools/lint/foo.c", hit, 1, 1, "FAIL")
            | clock_case(&re, "platform/modules/platform/src/clock.c", hit, 0, 0, "FAIL")
            | clock_case(&re, "tools/lint/foo.c", marked, 0, 0, "FAIL");
    const char *oldm = getenv("ZCL_LINT_MODE");
    if (setenv("ZCL_LINT_MODE", "WARN", 1) != 0) bad = 1;
    bad |= clock_case(&re, "tools/lint/foo.c", hit, 1, 0, clock_mode());
    if (oldm) (void)setenv("ZCL_LINT_MODE", oldm, 1);
    else (void)unsetenv("ZCL_LINT_MODE");
    (void)lint_filter_excluded;
    (void)lint_annotate_stray;
    (void)repo_shape_room_dirs;
    regfree(&re);
    return st_ok(bad, "check_no_raw_clock_outside_platform selftest: OK\n");
}

struct lint_gate {
    const char *name;
    int (*run)(int argc, char **argv);
    int (*selftest)(void);
};

static const struct lint_gate k_gates[] = {
    { "check-no-python", check_no_python_run, check_no_python_selftest },
    { "check-malloc", check_malloc_run, check_malloc_selftest },
    { "check-dev-proof-native-fast-path", check_dev_proof_native_fast_path_run,
      check_dev_proof_native_fast_path_selftest },
    { "check-before-save-hooks", check_before_save_hooks_run, check_before_save_hooks_selftest },
    { "check-pthread-create", check_pthread_create_run, check_pthread_create_selftest },
    { "check-silent-error-returns", check_silent_error_returns_run,
      check_silent_error_returns_selftest },
    { "check-no-gnu-va-args", check_no_gnu_va_args_run, check_no_gnu_va_args_selftest },
    { "check-sysinit-ordering", check_sysinit_ordering_run, check_sysinit_ordering_selftest },
    { "check-no-raw-clock-outside-platform", check_no_raw_clock_outside_platform_run,
      check_no_raw_clock_outside_platform_selftest },
};

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--list") == 0) {
        for (size_t i = 0; i < sizeof k_gates / sizeof k_gates[0]; i++)
            printf("%s\n", k_gates[i].name);
        return 0;
    }
    if (argc < 2)
        return die("z23-lint: usage: z23-lint <gate-name> [--selftest] | z23-lint <gate-name> [args...] | --list\n",
                   "");
    const struct lint_gate *g = NULL;
    for (size_t i = 0; i < sizeof k_gates / sizeof k_gates[0]; i++) {
        if (strcmp(argv[1], k_gates[i].name) == 0)
            g = &k_gates[i];
    }
    if (!g)
        return die("z23-lint: unknown gate: %s\n", argv[1]);
    if (argc >= 3 && strcmp(argv[2], "--selftest") == 0)
        return g->selftest();
    return g->run(argc - 2, argv + 2);
}
