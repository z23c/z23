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
#include <sys/wait.h>
#include <unistd.h>

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

static int cmd_done(const char *cmd, int st, int allow_exit1)
{
    if (st == 0)
        return 0;
    if (allow_exit1 && st != -1 && WIFEXITED(st) && WEXITSTATUS(st) == 1)
        return 0;
    return die("z23-lint: command failed (%s)\n", cmd);
}

static int each_zpath_st(const char *cmd, int allow_exit1,
                         int (*fn)(const char *, void *), void *ctx)
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
    return cmd_done(cmd, st, allow_exit1);
}

static int each_zpath(const char *cmd, int (*fn)(const char *, void *), void *ctx)
{
    return each_zpath_st(cmd, 0, fn, ctx);
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
            else if (S_ISREG(st.st_mode) && nl >= 2
                     && ((hdrs == 2 && nl >= 4 && memcmp(name + nl - 4, ".def", 4) == 0)
                         || (hdrs != 2 && name[nl - 2] == '.'
                             && (name[nl - 1] == 'c' || (hdrs && name[nl - 1] == 'h')))))
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

struct clock_acc { regex_t *re; char *buf; size_t cap, used;
                   int (*keep)(const char *, const char *); int raw; };

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
    if (a->keep && !a->keep(path, "")) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->re, line, 0, NULL, 0) != 0) continue;
        a->raw++;
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (a->keep && !a->keep(path, line)) continue;
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
    struct clock_acc a = {
        .re = &re, .buf = matches, .cap = sizeof matches, .used = 0, .keep = clock_keep
    };
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

static int keep_case(int (*keep)(const char *, const char *), const regex_t *re,
                     const char *path, const char *text,
                     int want_n, int want_rc, const char *mode)
{
    char buf[256] = {0};
    int n = 0;
    if (regexec(re, text, 0, NULL, 0) == 0 && keep(path, text)
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
            | keep_case(clock_keep, &re, "tools/lint/foo.c", "int x = 1;", 0, 0, "FAIL")
            | keep_case(clock_keep, &re, "tools/lint/foo.c", hit, 1, 1, "FAIL")
            | keep_case(clock_keep, &re, "platform/modules/platform/src/clock.c", hit, 0, 0, "FAIL")
            | keep_case(clock_keep, &re, "tools/lint/foo.c", marked, 0, 0, "FAIL");
    const char *oldm = getenv("ZCL_LINT_MODE");
    if (setenv("ZCL_LINT_MODE", "WARN", 1) != 0) bad = 1;
    bad |= keep_case(clock_keep, &re, "tools/lint/foo.c", hit, 1, 0, clock_mode());
    if (oldm) (void)setenv("ZCL_LINT_MODE", oldm, 1);
    else (void)unsetenv("ZCL_LINT_MODE");
    (void)lint_filter_excluded;
    (void)lint_annotate_stray;
    regfree(&re);
    return st_ok(bad, "check_no_raw_clock_outside_platform selftest: OK\n");
}

static int so_keep(const char *path, const char *text)
{
    const char *t = text;
    while (isspace((unsigned char)*t)) t++;
    return strncmp(path, "tests/", 6) && !strstr(text, "// shellout-ok")
        && *t != '*' && !(t[0] == '/' && (t[1] == '/' || t[1] == '*'));
}

static int so_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED, "(^|[^[:alnum:]_])sys" "tem[[:space:]]*\\(|",
                       "(^|[^[:alnum:]_])po" "pen[[:space:]]*\\(|",
                       "(^|[^[:alnum:]_])exec" "lp[[:space:]]*\\(", "");
}

static int so_summary(int v, const char *mode)
{
    return (printf("[check_no_shellouts] %d violation(s) found (mode: %s)\n", v, mode) < 0
            || puts("[check_no_shellouts] the node must not shell out — use platform/modules/util spawn") < 0
            || puts("[check_no_shellouts] (zcl_spawn_detached/zcl_spawn_capture) or") < 0
            || puts("[check_no_shellouts] platform/modules/util file_tree_ops (zcl_tree_copy/zcl_tree_remove);") < 0
            || puts("[check_no_shellouts] add // shellout-ok for a documented, reviewed exception") < 0)
               ? die("z23-lint: write failed\n", "") : 0;
}

static int check_no_shellouts_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    regex_t re;
    int rc = so_comp(&re), v = 0;
    if (rc) return rc;
    char matches[CLK_MATCH] = {0};
    struct clock_acc a = { .re = &re, .buf = matches, .cap = sizeof matches, .keep = so_keep };
    static const char *const roots[] = { "core", "engine", "contexts", "cognition", "platform" };
    rc = clock_walk(roots, sizeof roots / sizeof roots[0], &a);
    if (rc == 0) rc = gate_count_and_report(matches, &v);
    if (rc == 0) rc = so_summary(v, clock_mode());
    regfree(&re);
    return rc ? rc : clock_grade(v, clock_mode());
}

static int check_no_shellouts_selftest(void)
{
    regex_t re;
    if (so_comp(&re)) return 2;
    char hit[48], marked[64], commented[56];
    snprintf(hit, sizeof hit, "    sys%s", "tem(\"rm -rf /tmp/x\");");
    snprintf(marked, sizeof marked, "%s // shellout-ok", hit);
    snprintf(commented, sizeof commented, "    // sys%s", "tem(\"x\");");
    int bad = keep_case(so_keep, &re, "engine/foo.c", "int x = 1;", 0, 0, "FAIL")
            | keep_case(so_keep, &re, "engine/foo.c", hit, 1, 1, "FAIL")
            | keep_case(so_keep, &re, "tests/foo.c", hit, 0, 0, "FAIL")
            | keep_case(so_keep, &re, "engine/foo.c", marked, 0, 0, "FAIL")
            | keep_case(so_keep, &re, "engine/foo.c", commented, 0, 0, "FAIL");
    const char *oldm = getenv("ZCL_LINT_MODE");
    if (setenv("ZCL_LINT_MODE", "WARN", 1) != 0) bad = 1;
    bad |= keep_case(so_keep, &re, "engine/foo.c", hit, 1, 0, clock_mode());
    if (oldm) (void)setenv("ZCL_LINT_MODE", oldm, 1);
    else (void)unsetenv("ZCL_LINT_MODE");
    regfree(&re);
    return st_ok(bad, "check_no_shellouts selftest: OK\n");
}

struct cc_acc { regex_t *leaf, *empty; char *buf; size_t cap, used;
                int n_files, n_leaf, n_empty; };

static int cc_comp(regex_t *leaf, regex_t *empty)
{
    return pair_comp(leaf, REG_EXTENDED,
                     "ZCL_COMMAND_(READY_READ|COMPAT_READ|PLANNED_READ|",
                     "PLANNED_COMMAND|COMPAT_COMMAND|READY_COMMAND|DEV_READ|DEV_COMMAND)\\(",
                     "", "", empty, REG_EXTENDED,
                     "\"[[:space:]]*\"[[:space:]]*,[[:space:]]*(0|[1-9][0-9]*|ZCL_COMMAND_[A-Z_]+)",
                     "", "", "");
}

static int cc_feed(struct cc_acc *a, const char *path, const char *line, int lineno)
{
    for (const char *p = line; ; ) {
        regmatch_t m;
        if (regexec(a->leaf, p, 1, &m, 0) != 0) break;
        a->n_leaf++;
        p += m.rm_eo > 0 ? (size_t)m.rm_eo : 1;
    }
    if (regexec(a->empty, line, 0, NULL, 0) != 0) return 0;
    int k = snprintf(a->buf + a->used, a->cap - a->used, "%s:%d:%s\n", path, lineno, line);
    if (ovf(k, a->cap - a->used)) return 2;
    a->used += (size_t)k;
    a->n_empty++;
    return 0;
}

static int scan_cc(const char *path, void *ctx)
{
    struct cc_acc *a = ctx;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    a->n_files++;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if ((rc = cc_feed(a, path, line, ++lineno)) != 0) break;
    }
    return fin(f, line, path, rc);
}

static int cc_msgs(int n_empty, int n_leaf, const char *hits, const char *mode)
{
    if (n_empty > 0) {
        if (fputs(hits, stdout) < 0
            || printf("[check_command_contract] %d leaf(s) with an empty/blank "
                      "semantics argument (mode: %s)\n", n_empty, mode) < 0
            || puts("  Every leaf must supply a specific one-line OUTPUT-interpretation") < 0
            || puts("  semantics (source/freshness/units/completeness) — not \"\" and not") < 0
            || puts("  a restatement of summary. See engine/modules/kernel/include/kernel/") < 0
            || puts("  command_registry.h (struct zcl_command_spec.semantics).") < 0)
            return die("z23-lint: write failed\n", "");
        if (strcmp(mode, "FAIL") == 0) return 1;
    }
    return printf("[check_command_contract] PASS (%d leaves, all with semantics)\n",
                  n_leaf) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int check_command_contract_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *dir = getenv("ZCL_COMMAND_CONTRACT_DIR");
    if (!dir || !dir[0]) dir = "engine/composition/commands";
    regex_t leaf, empty;
    int cr = cc_comp(&leaf, &empty);
    if (cr) return cr;
    char hits[CLK_MATCH] = {0}, hint[4096];
    struct cc_acc a = { .leaf = &leaf, .empty = &empty, .buf = hits, .cap = sizeof hits };
    int rc = walk_src(dir, 2, scan_cc, &a);
    if (rc == 0 && ovf(snprintf(hint, sizeof hint, "no *.def under: %s", dir), sizeof hint))
        rc = 2;
    if (rc == 0)
        rc = gate_require_scanned(a.n_files, 1, "check_command_contract", hint);
    if (rc == 0)
        rc = gate_require_scanned(a.n_leaf, 125, "check_command_contract",
                                  "leaf-macro population collapsed under floor");
    if (rc == 0) rc = cc_msgs(a.n_empty, a.n_leaf, hits, clock_mode());
    drop2(&leaf, &empty);
    return rc;
}

static int cc_fatal(int count, int floor, const char *hint, const char *need)
{
    int save = dup(STDERR_FILENO);
    FILE *tf = tmpfile();
    char buf[2048] = {0};
    if (save < 0 || !tf) return 1;
    if (dup2(fileno(tf), STDERR_FILENO) < 0) { close(save); fclose(tf); return 1; }
    int rc = gate_require_scanned(count, floor, "check_command_contract", hint);
    fflush(stderr);
    (void)dup2(save, STDERR_FILENO);
    close(save);
    rewind(tf);
    if (fread(buf, 1, sizeof buf - 1, tf) == 0) buf[0] = '\0';
    fclose(tf);
    return rc != 2 || !strstr(buf, "FATAL") || !strstr(buf, need);
}

static int check_command_contract_selftest(void)
{
    regex_t leaf, empty;
    if (cc_comp(&leaf, &empty)) return 2;
    char hits[256] = {0};
    struct cc_acc a = { .leaf = &leaf, .empty = &empty, .buf = hits, .cap = sizeof hits };
    const char *okl = "ZCL_COMMAND_READY_READ(\"n\", \"s\", \"height from tip\", 0)";
    const char *badl = "ZCL_COMMAND_READY_READ(\"n\", \"s\", \"\", 0)";
    int bad = cc_feed(&a, "x.def", okl, 1) || a.n_leaf != 1 || a.n_empty != 0;
    a.n_leaf = a.n_empty = 0;
    a.used = 0;
    hits[0] = '\0';
    bad |= cc_feed(&a, "x.def", badl, 1) || a.n_leaf != 1 || a.n_empty != 1
        || clock_grade(a.n_empty, "FAIL") != 1 || clock_grade(a.n_empty, "WARN") != 0;
    drop2(&leaf, &empty);
    bad |= cc_fatal(0, 1, "no *.def under: empty", "no *.def under:")
        | cc_fatal(0, 125, "leaf-macro population collapsed under floor",
                   "leaf-macro population collapsed under floor");
    return st_ok(bad, "check_command_contract selftest: OK\n");
}

static const char *const k_wf_allow[] = {
    "engine/modules/storage/src/chain_segment.c",
    "engine/modules/storage/include/storage/chain_segment.h",
    "engine/services/src/segment_sealer_service.c",
    "engine/controllers/src/chain_segment_controller.c",
    "engine/conditions/src/segment_corruption.c",
};

static int wf_allowed(const char *path)
{
    for (size_t i = 0; i < sizeof k_wf_allow / sizeof k_wf_allow[0]; i++)
        if (strcmp(path, k_wf_allow[i]) == 0) return 1;
    return 0;
}

static int wf_keep(const char *path, const char *text)
{
    const char *t = text;
    while (isspace((unsigned char)*t)) t++;
    return strncmp(path, "tests/", 6) && !strstr(text, "// writer-below-frontier-ok")
        && *t != '*' && !(t[0] == '/' && (t[1] == '/' || t[1] == '*'))
        && (!*t || !wf_allowed(path));
}

static int wf_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED,
                       "(^|[^[:alnum:]_])chain_segment_seal" "_range[[:space:]]*\\(|",
                       "(^|[^[:alnum:]_])chain_segment_manifest" "_rebuild[[:space:]]*\\(",
                       "", "");
}

static int wf_need_files(void)
{
    for (size_t i = 0; i < sizeof k_wf_allow / sizeof k_wf_allow[0]; i++) {
        struct stat st;
        if (stat(k_wf_allow[i], &st) == 0 && S_ISREG(st.st_mode)) continue;
        fprintf(stderr, "check_no_writer_below_sealed_frontier: FATAL — "
                        "designated writer file '%s' is missing.\n", k_wf_allow[i]);
        fputs("  The sealed-store write surface moved; update this gate's\n"
              "  ALLOWLIST deliberately instead of letting the scan go hollow.\n",
              stderr);
        return 2;
    }
    return 0;
}

static int wf_summary(int raw, int v, const char *mode)
{
    return (printf("[check_no_writer_below_sealed_frontier] scanned %d "
                   "call/declaration site(s); %d violation(s) (mode: %s)\n",
                   raw, v, mode) < 0
            || puts("[check_no_writer_below_sealed_frontier] only the "
                    "sealer/RPC/healer/writer may call") < 0
            || puts("[check_no_writer_below_sealed_frontier] chain_segment_seal"
                    "_range() or chain_segment_manifest" "_rebuild();") < 0
            || puts("[check_no_writer_below_sealed_frontier] add // "
                    "writer-below-frontier-ok for a documented, reviewed exception") < 0)
               ? die("z23-lint: write failed\n", "") : 0;
}

static int check_no_writer_below_sealed_frontier_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    int rc = wf_need_files();
    if (rc) return rc;
    regex_t re;
    rc = wf_comp(&re);
    if (rc) return rc;
    char matches[CLK_MATCH] = {0};
    struct clock_acc a = { .re = &re, .buf = matches, .cap = sizeof matches, .keep = wf_keep };
    static const char *const roots[] = { "core", "engine", "contexts", "cognition", "platform" };
    int n_roots = 0;
    for (size_t i = 0; i < sizeof roots / sizeof roots[0]; i++) {
        struct stat st;
        if (stat(roots[i], &st) == 0 && S_ISDIR(st.st_mode)) n_roots++;
    }
    rc = gate_require_scanned(n_roots, 5, "check_no_writer_below_sealed_frontier",
                              "expected all five production authorities to exist");
    if (rc == 0) rc = clock_walk(roots, sizeof roots / sizeof roots[0], &a);
    if (rc == 0)
        rc = gate_require_scanned(a.raw, 5, "check_no_writer_below_sealed_frontier",
                                  "chain_segment_seal" "_range/chain_segment_manifest"
                                  "_rebuild appear to have been renamed");
    int v = 0;
    if (rc == 0) rc = gate_count_and_report(matches, &v);
    if (rc == 0) rc = wf_summary(a.raw, v, clock_mode());
    regfree(&re);
    return rc ? rc : clock_grade(v, clock_mode());
}

static int check_no_writer_below_sealed_frontier_selftest(void)
{
    regex_t re;
    if (wf_comp(&re)) return 2;
    char hit[48], marked[80], commented[56];
    snprintf(hit, sizeof hit, "    chain_segment_seal%s", "_range(s, 0, 1);");
    snprintf(marked, sizeof marked, "%s // writer-below-frontier-ok", hit);
    snprintf(commented, sizeof commented, "    // chain_segment_seal%s", "_range(s, 0, 1);");
    int bad = keep_case(wf_keep, &re, "engine/foo.c", "int x = 1;", 0, 0, "FAIL")
            | keep_case(wf_keep, &re, "engine/foo.c", hit, 1, 1, "FAIL")
            | keep_case(wf_keep, &re, k_wf_allow[0], hit, 0, 0, "FAIL")
            | keep_case(wf_keep, &re, "tests/foo.c", hit, 0, 0, "FAIL")
            | keep_case(wf_keep, &re, "engine/foo.c", marked, 0, 0, "FAIL")
            | keep_case(wf_keep, &re, "engine/foo.c", commented, 0, 0, "FAIL");
    const char *oldm = getenv("ZCL_LINT_MODE");
    if (setenv("ZCL_LINT_MODE", "WARN", 1) != 0) bad = 1;
    bad |= keep_case(wf_keep, &re, "engine/foo.c", hit, 1, 0, clock_mode());
    if (oldm) (void)setenv("ZCL_LINT_MODE", oldm, 1);
    else (void)unsetenv("ZCL_LINT_MODE");
    regfree(&re);
    return st_ok(bad, "check_no_writer_below_sealed_frontier selftest: OK\n");
}

enum { SR_ALLOW = 256, SR_NAME = 96, SR_STRAY = 128 };
struct sr_set { char n[SR_ALLOW][SR_NAME]; int count; };
struct sr_acc { struct sr_set allowed; int tracked; };

static int sr_has(const struct sr_set *s, const char *name)
{ for (int i = 0; i < s->count; i++) if (!strcmp(s->n[i], name)) return 1; return 0; }

static int sr_add(struct sr_set *s, const char *name)
{
    size_t n = strlen(name);
    if (sr_has(s, name)) return 0;
    if (s->count >= SR_ALLOW || n >= SR_NAME) return die("z23-lint: stray-root overflow\n", "");
    memcpy(s->n[s->count++], name, n + 1);
    return 0;
}

static int sr_load(struct sr_set *s, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *h = strchr(line, '#'), *p = line;
        if (h) *h = '\0';
        while (*p && isspace((unsigned char)*p)) p++;
        size_t n = strlen(p);
        while (n && isspace((unsigned char)p[n - 1])) p[--n] = '\0';
        if (n) rc = sr_add(s, p);
    }
    return fin(f, line, path, rc);
}

static void sr_del(struct sr_set *s, const char *name)
{
    for (int i = 0; i < s->count; i++)
        if (!strcmp(s->n[i], name)) {
            if (i + 1 < s->count) memcpy(s->n[i], s->n[s->count - 1], SR_NAME);
            s->count--;
            return;
        }
}

static const char *const k_sr_root_allowed[] = {
    ".git", "build", "vendor", "test-tmp", "compile_commands.json",
    ".cache", ".codeindex", ".zvcs", ".core-unseal-token", ".zcl_test_render",
    "chaos-output", ".antigravitycli", ".gemini", ".aider", ".vscode", ".idea",
    "tags", "TAGS", ".DS_Store",
};

static int sr_seed(struct sr_set *s)
{
    for (size_t i = 0; i < sizeof k_sr_root_allowed / sizeof k_sr_root_allowed[0]; i++)
        if (sr_add(s, k_sr_root_allowed[i])) return 2;
    return 0;
}
static int sr_on_track(const char *path, void *ctx)
{
    struct sr_acc *a = ctx;
    const char *sl = strchr(path, '/');
    size_t n = sl ? (size_t)(sl - path) : strlen(path);
    char seg[SR_NAME];
    a->tracked++;
    if (n >= sizeof seg) return die("z23-lint: stray-root overflow\n", "");
    memcpy(seg, path, n); seg[n] = '\0';
    return sr_add(&a->allowed, seg);
}
static int sr_ok_name(const char *name, const struct sr_set *al)
{
    const char *base = strncmp(name, ".aider", 6) == 0 ? ".aider" : name;
    return sr_has(al, base) || !strncmp(name, "core.", 5) || !strncmp(name, "vgcore.", 7);
}

static int sr_feed(const struct sr_set *al, const char *const *names, int n,
                   char stray[][SR_NAME], int max, int *ns, int *scanned)
{
    *ns = 0;
    *scanned = 0;
    for (int i = 0; i < n; i++) {
        if (!names[i][0] || !strcmp(names[i], ".") || !strcmp(names[i], "..")) continue;
        (*scanned)++;
        if (sr_ok_name(names[i], al)) continue;
        if (*ns >= max || strlen(names[i]) >= SR_NAME)
            return die("z23-lint: stray-root overflow\n", "");
        memcpy(stray[(*ns)++], names[i], strlen(names[i]) + 1);
    }
    return 0;
}

static int sr_report(char stray[][SR_NAME], int n)
{
    if (fprintf(stderr, "FAIL: %d stray entr(y/ies) in the repository root\n", n) < 0
        || fputs("  The root is a curated list: source areas, top-level docs, and a\n"
                 "  short allowlist of generated/local entries. These are neither.\n"
                 "  They are gitignored, so 'git status' stays clean while 'ls' shows\n"
                 "  a junk drawer — that is exactly what this gate exists to stop.\n",
                 stderr) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < n; i++)
        if (fprintf(stderr, "    %s [stray root entry]\n", stray[i]) < 0)
            return die("z23-lint: write failed\n", "");
    if (fputs("  Fix at the WRITER, not here: a test writes its scratch under\n"
              "  ./test-tmp/ (test_make_tmpdir in tests/harness/include/test/test_core.h),\n"
              "  a script writes its log under a state/log dir. 'git add' it if it\n"
              "  is real new content; delete it if it is debris.\n", stderr) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int check_no_stray_root_files_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    struct sr_acc a = {0};
    int rc = sr_seed(&a.allowed);
    if (rc == 0) rc = each_zpath(k_ls_all, sr_on_track, &a);
    if (rc == 0)
        rc = gate_require_scanned(a.tracked, 100, "check-no-stray-root-files",
                "git ls-files returned almost nothing — not a git checkout, or the wrong cwd.");
    if (rc) return rc;
    const char *extra = getenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST");
    if (extra && extra[0]) sr_del(&a.allowed, extra);
    struct dirent **names = NULL;
    int nd = scandir(".", &names, NULL, alphasort);
    if (nd < 0) return die("z23-lint: cannot scan %s\n", ".");
    char stray[SR_STRAY][SR_NAME];
    int ns = 0, scanned = 0;
    for (int i = 0; i < nd; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") && strcmp(name, "..")) {
            scanned++;
            if (!sr_ok_name(name, &a.allowed)) {
                if (ns >= SR_STRAY || strlen(name) >= SR_NAME)
                    rc = die("z23-lint: stray-root overflow\n", "");
                else memcpy(stray[ns++], name, strlen(name) + 1);
            }
        }
        free(names[i]);
    }
    free(names);
    if (rc == 0)
        rc = gate_require_scanned(scanned, 20, "check-no-stray-root-files",
                                  "the repo root listed fewer than 20 entries — wrong cwd?");
    if (rc) return rc;
    if (ns) return sr_report(stray, ns);
    return printf("[check_no_stray_root_files] scanned %d root entr(y/ies); 0 strays\n",
                  scanned) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int check_no_stray_root_files_selftest(void)
{
    struct sr_set al = {0};
    char stray[8][SR_NAME];
    int ns = 0, sc = 0, bad = sr_seed(&al) != 0;
    const char *okn[] = { ".git", "build", "vendor", "test-tmp", ".aider" };
    bad |= sr_feed(&al, okn, 5, stray, 8, &ns, &sc) || ns != 0 || sc != 5;
    const char *badn[] = { ".git", "junk.db" };
    ns = sc = 0;
    bad |= sr_feed(&al, badn, 2, stray, 8, &ns, &sc) || ns != 1
        || strcmp(stray[0], "junk.db") || sr_report(stray, ns) != 1;
    const char *aid[] = { ".aider.tags.cache.v3" };
    ns = sc = 0;
    bad |= sr_feed(&al, aid, 1, stray, 8, &ns, &sc) || ns != 0;
    const char *core[] = { "core.1234", "vgcore.9" };
    ns = sc = 0;
    bad |= sr_feed(&al, core, 2, stray, 8, &ns, &sc) || ns != 0;
    const char *old = getenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST");
    if (setenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST", "build", 1) != 0) bad = 1;
    {
        const char *e = getenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST");
        if (e && e[0]) sr_del(&al, e);
    }
    const char *ex[] = { "build" };
    ns = sc = 0;
    bad |= sr_feed(&al, ex, 1, stray, 8, &ns, &sc) || ns != 1 || strcmp(stray[0], "build");
    if (old) (void)setenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST", old, 1);
    else (void)unsetenv("ZCL_ROOT_STRAY_EXTRA_FOR_TEST");
    return st_ok(bad, "check_no_stray_root_files selftest: OK\n");
}

static int ps_hit_line(const char *s)
{
    return strstr(s, "\"/proc/" "self") || strstr(s, "\"/proc/" "uptime");
}
static int ps_skip(const char *path, const struct sr_set *base)
{
    return lint_path_is_excluded(path)
        || strncmp(path, "platform/modules/platform/", 26) == 0 || sr_has(base, path);
}
struct ps_acc { const struct sr_set *base; char (*hit)[192]; int n, max; };
static int scan_ps(const char *path, void *ctx)
{
    struct ps_acc *a = ctx;
    if (ps_skip(path, a->base)) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    int rc = 0, found = 0;
    while (!found && getline(&line, &cap, f) >= 0) found = ps_hit_line(line);
    if (found) {
        size_t n = strlen(path);
        if (a->n >= a->max || n >= 192) rc = die("z23-lint: derived buffer overflow\n", "");
        else memcpy(a->hit[a->n++], path, n + 1);
    }
    return fin(f, line, path, rc);
}

static int check_proc_self_shim_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    struct sr_set base = {0};
    int rc = sr_load(&base, "tools/lint/proc_self_shim_baseline.txt");
    if (rc) return rc;
    char hit[64][192];
    struct ps_acc a = { .base = &base, .hit = hit, .max = 64 };
    static const char *const roots[] = { "app", "config", "lib", "tools" };
    for (size_t i = 0; rc == 0 && i < sizeof roots / sizeof roots[0]; i++)
        rc = walk_src(roots[i], 0, scan_ps, &a);
    if (rc) return rc;
    if (!a.n)
        return puts("check_proc_self_shim: clean — no new raw /proc/self or /proc/uptime reads") < 0
                   ? die("z23-lint: write failed\n", "") : 0;
    char cwd[4096], bpath[4096];
    if (!getcwd(cwd, sizeof cwd)) return die("z23-lint: getcwd failed\n", "");
    if (ovf(snprintf(bpath, sizeof bpath, "%s/tools/lint/proc_self_shim_baseline.txt", cwd),
            sizeof bpath))
        return 2;
    if (fprintf(stderr, "check_proc_self_shim: raw /proc/self or /proc/uptime read(s) "
                        "outside platform/modules/platform/, not in %s:\n", bpath) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < a.n; i++)
        if (fprintf(stderr, "  %s\n", a.hit[i]) < 0)
            return die("z23-lint: write failed\n", "");
    if (fprintf(stderr, "\nRoute through platform/os_proc.h, or add the file to %s with a "
                        "reason if genuinely exempt (e.g. async-signal-safety, per "
                        "engine/modules/sim/src/postmortem.c:1040).\n", bpath) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int check_proc_self_shim_selftest(void)
{
    const char *hit = "printf(\"%s\", \"/proc/" "self/exe\");";
    struct sr_set empty = {0}, base = {0};
    int bad = !ps_hit_line(hit) || ps_hit_line("int x;") || ps_hit_line("/proc/" "self");
    bad |= ps_skip("tools/foo.c", &empty) || !ps_skip("platform/modules/platform/os.c", &empty);
    if (sr_add(&base, "tools/foo.c")) return 2;
    bad |= !(ps_hit_line(hit) && !ps_skip("tools/foo.c", &empty));
    bad |= ps_hit_line(hit) && !ps_skip("tools/foo.c", &base);
    const char *old = getenv("ZCL_LINT_PRODUCTION_SCAN");
    if (setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1) != 0) bad = 1;
    bad |= !lint_path_is_excluded("tools/_xfixture.c") || !ps_skip("tools/_xfixture.c", &empty);
    if (old) (void)setenv("ZCL_LINT_PRODUCTION_SCAN", old, 1);
    else (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    bad |= lint_path_is_excluded("tools/_xfixture.c") || ps_skip("tools/_xfixture.c", &empty);
    return st_ok(bad, "check_proc_self_shim selftest: OK\n");
}

static const char *const k_simd_del[] = {
    "keccak_x4_available", "core/modules/crypto/src/keccak_x4.c",
};
static int has_ci(const char *h, const char *n)
{
    size_t nlen = strlen(n);
    for (; *h; h++) {
        size_t i = 0;
        while (i < nlen && h[i]
               && tolower((unsigned char)h[i]) == tolower((unsigned char)n[i])) i++;
        if (i == nlen) return 1;
    }
    return 0;
}
static int mem_local(const char *t)
{
    return strstr(t, "crypto/simd_dispatch.h")
        || (has_ci(t, "xgetbv") && has_ci(t, "osxsave"));
}
static int mem_del(const char *t)
{
    for (size_t i = 0; i + 1 < sizeof k_simd_del / sizeof k_simd_del[0]; i += 2)
        if (strstr(t, k_simd_del[i])) return 1;
    return 0;
}
static int file_has(const char *path, const char *nd, int ci, int *found)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char *line = NULL;
    size_t cap = 0;
    *found = 0;
    while (!*found && getline(&line, &cap, f) >= 0)
        *found = ci ? has_ci(line, nd) : strstr(line, nd) != NULL;
    return fin(f, line, path, 0);
}
static int simd_local_file(const char *path, int *ok)
{
    int a = 0, b = 0, c = 0, rc = file_has(path, "crypto/simd_dispatch.h", 0, &a);
    if (rc) return rc;
    if (a) { *ok = 1; return 0; }
    rc = file_has(path, "xgetbv", 1, &b);
    if (rc) return rc;
    rc = file_has(path, "osxsave", 1, &c);
    if (rc) return rc;
    *ok = b && c;
    return 0;
}
struct simd_acc { char f[64][192]; int n; };
/* git grep -l of tracked *.c (not a filesystem walk): untracked probes do not count. */
static const char k_simd_grep[] =
    "git grep -l -z -E '__attribute__\\(\\(" "target\\(\"avx' -- '*.c'";
static int simd_add_path(const char *path, void *ctx)
{
    struct simd_acc *a = ctx;
    size_t n = strlen(path);
    if (a->n >= 64 || n >= 192) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(a->f[a->n++], path, n + 1);
    return 0;
}
static int simd_pcmp(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }
static int simd_open(const char *path, int rc)
{ return rc < 0 ? die("z23-lint: cannot open %s\n", path) : rc; }

static int check_simd_os_support_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    struct simd_acc a = {0};
    int rc = each_zpath_st(k_simd_grep, 1, simd_add_path, &a), v = 0;
    if (rc == 0 && a.n > 1)
        qsort(a.f, (size_t)a.n, sizeof a.f[0], simd_pcmp);
    if (rc == 0)
        rc = gate_require_scanned(a.n, 1, "check_simd_os_support",
                                  "expected at least core/modules/crypto/src/blake2b_avx2.c "
                                  "to carry target(\"avx...\")");
    for (size_t i = 0; rc == 0 && i + 1 < sizeof k_simd_del / sizeof k_simd_del[0]; i += 2) {
        const char *name = k_simd_del[i], *file = k_simd_del[i + 1];
        struct stat st;
        if (stat(file, &st) != 0 || !S_ISREG(st.st_mode)) {
            if (fprintf(stderr, "%s: delegate '%s' names a file that no longer exists\n",
                        file, name) < 0)
                return die("z23-lint: write failed\n", "");
            v++;
            continue;
        }
        int ok = 0;
        rc = simd_open(file, simd_local_file(file, &ok));
        if (rc) return rc;
        if (!ok) {
            if (fprintf(stderr, "%s: defines delegate '%s' but performs no OS-state check\n",
                        file, name) < 0
                || fputs("    -> every caller that relies on it is now unguarded\n", stderr) < 0)
                return die("z23-lint: write failed\n", "");
            v++;
        }
    }
    for (int i = 0; rc == 0 && i < a.n; i++) {
        int ok = 0, del = 0;
        rc = simd_open(a.f[i], simd_local_file(a.f[i], &ok));
        if (rc) return rc;
        if (ok) continue;
        for (size_t d = 0; d + 1 < sizeof k_simd_del / sizeof k_simd_del[0]; d += 2) {
            int fnd = 0;
            rc = simd_open(a.f[i], file_has(a.f[i], k_simd_del[d], 0, &fnd));
            if (rc) return rc;
            if (fnd) { del = 1; break; }
        }
        if (del) continue;
        if (fprintf(stderr, "%s: dispatches into target(\"avx...\") code with no OS-state check\n",
                    a.f[i]) < 0
            || fputs("    -> #include \"crypto/simd_dispatch.h\" and gate the dispatch on\n",
                     stderr) < 0
            || fputs("       simd_host_has_avx2() / simd_host_has_avx512f()\n", stderr) < 0)
            return die("z23-lint: write failed\n", "");
        v++;
    }
    if (rc) return rc;
    const char *mode = clock_mode();
    if (printf("[check_simd_os_support] scanned %d AVX dispatch file(s), %d violation(s) "
               "(mode: %s)\n", a.n, v, mode) < 0
        || puts("[check_simd_os_support] CPUID says what the CPU decodes; XCR0 says what") < 0
        || puts("[check_simd_os_support] the OS will save. Dispatching on the first alone") < 0
        || puts("[check_simd_os_support] is a SIGILL on a host booted with the state off.") < 0)
        return die("z23-lint: write failed\n", "");
    return clock_grade(v, mode);
}

static int check_simd_os_support_selftest(void)
{
    const char *avx = "__attribute__((target(\"" "avx2\"))) void zz(void) {}";
    char a[160], b[200], c[180], d[180], e[200];
    if (ovf(snprintf(a, sizeof a, "%s", avx), sizeof a)
        || ovf(snprintf(b, sizeof b, "#include \"crypto/simd_dispatch.h\"\n%s", avx), sizeof b)
        || ovf(snprintf(c, sizeof c, "XGETBV osxsave\n%s", avx), sizeof c)
        || ovf(snprintf(d, sizeof d, "xgetbv\n%s", avx), sizeof d)
        || ovf(snprintf(e, sizeof e, "keccak_x4_available\n%s", avx), sizeof e))
        return 2;
    int bad = mem_local(a) || !mem_local(b) || !mem_local(c) || mem_local(d)
            || !mem_del(e) || mem_del(a)
            || mem_local(a) || mem_del(a)
            || !(!mem_local(d) && !mem_del(d))
            || !(!mem_local(e) && mem_del(e))
            || mem_local("void keccak_x4_available(void) {}");
    return st_ok(bad, "check_simd_os_support selftest: OK\n");
}

static int slurp_popen_lines(const char *cmd, int allow_exit1, char *out, size_t cap,
                             size_t *used)
{
    FILE *p = popen(cmd, "r");
    if (!p) return die("z23-lint: popen failed (%s)\n", cmd);
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int rc = 0;
    *used = 0;
    out[0] = '\0';
    while ((n = getline(&line, &lcap, p)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        if (n <= 0) continue;
        int k = snprintf(out + *used, cap - *used, "%s\n", line);
        if (ovf(k, cap - *used)) { rc = 2; break; }
        *used += (size_t)k;
    }
    if (rc == 0 && ferror(p)) rc = die("z23-lint: read failed (%s)\n", cmd);
    free(line);
    int st = pclose(p);
    if (rc) return rc;
    return cmd_done(cmd, st, allow_exit1);
}

static int c23_ends(const char *path, const char *suf)
{
    size_t n = strlen(path), m = strlen(suf);
    return n >= m && memcmp(path + n - m, suf, m) == 0;
}
static int c23_seg_end(const char *path, const char *name)
{
    size_t n = strlen(path), m = strlen(name);
    if (n < m || memcmp(path + n - m, name, m) != 0) return 0;
    return n == m || path[n - m - 1] == '/';
}
static int c23_path_hit(const char *path)
{
    static const char dir[] = { '.', 'c', 'a', 'r', 'g', 'o', '/', '\0' };
    static const char mid[] = { '/', '.', 'c', 'a', 'r', 'g', 'o', '/', '\0' };
    if (c23_seg_end(path, "Cargo.toml") || c23_seg_end(path, "Cargo.lock")
        || c23_seg_end(path, "build.rs") || c23_ends(path, ".rs"))
        return 1;
    return !strncmp(path, dir, 7) || strstr(path, mid) != NULL;
}
static int c23_skip_ref(const char *path)
{
    return !strcmp(path, "contexts/wallet/domain/src/mnemonic.c")
        || !strcmp(path, "core/modules/sapling/src/circuit_gadgets.c");
}
static int c23_fill_pat(char *pat, size_t cap)
{
    return ovf(snprintf(pat, cap, "%s%s%s%s%s",
                       "ZCL_WITH_", "RUST|librust", "zcash\\.a|librust",
                       "zcash_[A-Za-z0-9_]*|-l" "rust[A-Za-z0-9_]*|",
                       "(^|[^A-Za-z0-9_])(car" "go|rust" "c)([^A-Za-z0-9_]|$)"), cap);
}
static int c23_comp(regex_t *re)
{
    char pat[256];
    int rc = c23_fill_pat(pat, sizeof pat);
    return rc ? rc : reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}
static int c23_grep_cmd(char *cmd, size_t cap)
{
    char pat[256];
    int rc = c23_fill_pat(pat, sizeof pat);
    if (rc) return rc;
    return ovf(snprintf(cmd, cap,
        "git grep -n -E '%s' -- Makefile config app core domain "
        "lib ports adapters packages src tools "
        "':!contexts/wallet/domain/src/mnemonic.c' "
        "':!core/modules/sapling/src/circuit_gadgets.c'", pat), cap);
}
struct c23_acc { char *paths; size_t pcap, plen; };
static int c23_on_track(const char *path, void *ctx)
{
    struct c23_acc *a = ctx;
    if (!c23_path_hit(path)) return 0;
    int k = snprintf(a->paths + a->plen, a->pcap - a->plen, "%s\n", path);
    if (ovf(k, a->pcap - a->plen)) return 2;
    a->plen += (size_t)k;
    return 0;
}

static int check_c23_only_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    char paths[CLK_MATCH] = {0}, refs[CLK_MATCH] = {0}, cmd[1024];
    struct c23_acc a = { .paths = paths, .pcap = sizeof paths };
    int rc = each_zpath(k_ls_all, c23_on_track, &a);
    if (rc == 0) rc = c23_grep_cmd(cmd, sizeof cmd);
    size_t rlen = 0;
    if (rc == 0) rc = slurp_popen_lines(cmd, 1, refs, sizeof refs, &rlen);
    if (rc) return rc;
    if (a.plen || rlen) {
        if (fputs("check_c23_only: FAIL — Z23 must have no Rust dependency\n", stderr) < 0)
            return die("z23-lint: write failed\n", "");
        if (a.plen && fwrite(paths, 1, a.plen, stderr) != a.plen)
            return die("z23-lint: write failed\n", "");
        if (rlen && fwrite(refs, 1, rlen, stderr) != rlen)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return fputs("check_c23_only: clean — no Rust source, manifest, build, link, or FFI path\n",
                 stdout) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int check_c23_only_selftest(void)
{
    regex_t re;
    int cr = c23_comp(&re);
    if (cr) return cr;
    char cg[24], lr[40], wr[24], pdir[24], pmid[32];
    if (snprintf(cg, sizeof cg, "car%s", "go build") >= (int)sizeof cg
        || snprintf(lr, sizeof lr, "cc main.o -l%s", "rustzcash") >= (int)sizeof lr
        || snprintf(wr, sizeof wr, "ZCL_WITH_%s=1", "RUST") >= (int)sizeof wr
        || snprintf(pdir, sizeof pdir, ".car%s", "go/config") >= (int)sizeof pdir
        || snprintf(pmid, sizeof pmid, "vendor/.car%s", "go/config") >= (int)sizeof pmid) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int bad = want("check_c23_only", &re, "cc -std=c23 main.c", 0)
            | want("check_c23_only", &re, cg, 1)
            | want("check_c23_only", &re, lr, 1)
            | want("check_c23_only", &re, wr, 1)
            | !c23_path_hit("pkg/Cargo.toml")
            | !c23_path_hit("x/Cargo.lock")
            | !c23_path_hit("x/build.rs")
            | !c23_path_hit("tools/zz_probe.rs")
            | !c23_path_hit(pdir)
            | !c23_path_hit(pmid)
            | c23_path_hit("tools/foo.c")
            | c23_path_hit("Cargo.tomlx")
            | !c23_skip_ref("contexts/wallet/domain/src/mnemonic.c")
            | !c23_skip_ref("core/modules/sapling/src/circuit_gadgets.c")
            | c23_skip_ref("tools/foo.c");
    regfree(&re);
    return st_ok(bad, "check_c23_only selftest: OK\n");
}

enum { HS_NEST = 64 };
struct hs_st {
    const regex_t *re;
    const char *path;
    char *buf;
    size_t cap, *used;
    int depth, dev_active, lineno;
    int dev_frame[HS_NEST], dev_branch[HS_NEST];
};
static int hs_dl_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED, "(^|[^[:alnum:]_])dl(open|sym|close)",
                       "[[:space:]]*[(]", "", "");
}
static const char *hs_after_hash(const char *line)
{
    while (*line == ' ' || *line == '\t') line++;
    if (*line != '#') return NULL;
    line++;
    while (*line == ' ' || *line == '\t') line++;
    return line;
}
static int hs_pp(const char *line)
{
    const char *p = hs_after_hash(line);
    if (!p) return 0;
    if (!strncmp(p, "ifdef", 5) && (p[5] == ' ' || p[5] == '\t')) {
        p += 5;
        while (*p == ' ' || *p == '\t') p++;
        if (!strncmp(p, "ZCL_DEV_BUILD", 13)) return 1;
        return 2;
    }
    if (p[0] == 'i' && p[1] == 'f') return 2;
    if (!strncmp(p, "elif", 4) || !strncmp(p, "else", 4)) return 3;
    if (!strncmp(p, "endif", 5)) return 4;
    return 0;
}
static int hs_feed(struct hs_st *s, const char *line)
{
    s->lineno++;
    int k = hs_pp(line);
    if (k == 1 || k == 2) {
        if (s->depth + 1 >= HS_NEST)
            return die("z23-lint: ifdef nest too deep: %s\n", s->path);
        s->depth++;
        s->dev_frame[s->depth] = (k == 1);
        s->dev_branch[s->depth] = (k == 1);
        if (k == 1) s->dev_active++;
        return 0;
    }
    if (k == 3) {
        if (s->depth > 0 && s->dev_frame[s->depth] && s->dev_branch[s->depth]) {
            s->dev_active--;
            s->dev_branch[s->depth] = 0;
        }
        return 0;
    }
    if (k == 4) {
        if (s->depth > 0) {
            if (s->dev_frame[s->depth] && s->dev_branch[s->depth]) s->dev_active--;
            s->dev_frame[s->depth] = 0;
            s->dev_branch[s->depth] = 0;
            s->depth--;
        }
        return 0;
    }
    if (regexec(s->re, line, 0, NULL, 0) != 0 || s->dev_active >= 1) return 0;
    int n = snprintf(s->buf + *s->used, s->cap - *s->used, "%s:%d: %s\n",
                     s->path, s->lineno, line);
    if (ovf(n, s->cap - *s->used)) return 2;
    *s->used += (size_t)n;
    return 0;
}
static int hs_scan_text(const char *text, const char *path, const regex_t *re,
                        char *buf, size_t cap, size_t *used)
{
    struct hs_st s = {
        .re = re, .path = path, .buf = buf, .cap = cap, .used = used,
        .depth = 0, .dev_active = 0, .lineno = 0
    };
    *used = 0;
    buf[0] = '\0';
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[4096];
        if (n >= sizeof line) return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        int rc = hs_feed(&s, line);
        if (rc) return rc;
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}
static int hs_scan_path(const char *path, const regex_t *re, char *buf, size_t cap,
                        size_t *used)
{
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    struct hs_st s = {
        .re = re, .path = path, .buf = buf, .cap = cap, .used = used,
        .depth = 0, .dev_active = 0, .lineno = 0
    };
    *used = 0;
    buf[0] = '\0';
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &lcap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        rc = hs_feed(&s, line);
        if (rc) break;
    }
    return fin(f, line, path, rc);
}
struct hs_out_acc { const regex_t *re; char *buf; size_t cap, used; };
static int scan_hs_out(const char *path, void *ctx)
{
    struct hs_out_acc *a = ctx;
    if (!strncmp(path, "engine/modules/hotswap/", 23)) return 0;
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
        int k = snprintf(a->buf + a->used, a->cap - a->used, "%s:%d:%s\n",
                         path, lineno, line);
        if (ovf(k, a->cap - a->used)) { rc = 2; break; }
        a->used += (size_t)k;
    }
    return fin(f, line, path, rc);
}
static int hs_each_src(const char *dir, const regex_t *re, int *saw)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0) return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    char bad[CLK_MATCH];
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") && strcmp(name, "..")) {
            char path[4096];
            struct stat st;
            size_t nl = strlen(name);
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISREG(st.st_mode) && nl >= 2 && name[nl - 2] == '.'
                     && name[nl - 1] == 'c') {
                size_t used = 0;
                rc = hs_scan_path(path, re, bad, sizeof bad, &used);
                if (rc == 0 && used) {
                    if (fputs(bad, stdout) < 0
                        || printf("FAIL: dl* call outside a #ifdef ZCL_DEV_BUILD region in %s\n",
                                  path) < 0)
                        rc = die("z23-lint: write failed\n", "");
                    else rc = 1;
                }
                if (saw) (*saw)++;
            }
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int check_hotswap_dev_only_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    regex_t re;
    int cr = hs_dl_comp(&re);
    if (cr) return cr;
    char hits[CLK_MATCH] = {0};
    struct hs_out_acc a = { .re = &re, .buf = hits, .cap = sizeof hits };
    static const char *const roots[] = {
        "app", "tools", "lib", "config", "src", "domain", "application", "adapters"
    };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof roots / sizeof roots[0]; i++)
        rc = walk_src(roots[i], 0, scan_hs_out, &a);
    if (rc == 0 && a.used) {
        if (fputs(hits, stdout) < 0
            || puts("FAIL: dlopen/dlsym/dlclose outside engine/modules/hotswap/ (release must be static)") < 0)
            rc = die("z23-lint: write failed\n", "");
        else rc = 1;
    }
    if (rc == 0) rc = hs_each_src("engine/modules/hotswap/src", &re, NULL);
    regfree(&re);
    if (rc) return rc;
    return puts("  OK: hot-swap dynamic loading is dev-only") < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int check_hotswap_dev_only_selftest(void)
{
    regex_t re;
    int cr = hs_dl_comp(&re);
    if (cr) return cr;
    char nested[160], elseb[160], inner[160], pfx[160], d1[64], d2[64], d3[48];
    char nbuf[256], ebuf[256], ibuf[256];
    size_t nused = 0, eused = 0, iused = 0;
    if (snprintf(nested, sizeof nested,
                 "#ifdef ZCL_DEV_BUILD\n#if defined(__APPLE__)\ndl%s(\"dev\", 0);\n"
                 "#endif\n#endif\n", "open") >= (int)sizeof nested
        || snprintf(elseb, sizeof elseb,
                    "#ifdef ZCL_DEV_BUILD\ndl%s(\"dev\", 0);\n#else\ndl%s(\"release\", 0);\n"
                    "#endif\n", "open", "open") >= (int)sizeof elseb
        || snprintf(inner, sizeof inner,
                    "#ifdef ZCL_DEV_BUILD\n#if 0\ndl%s(\"inner\", 0);\n#endif\n#endif\n",
                    "open") >= (int)sizeof inner
        || snprintf(pfx, sizeof pfx, "%s\n%s\n%s\n",
                    "static void *vfs_dir_xdlopen(void);",
                    "static void *vfs_dir_xdlsym(void);",
                    "static void vfs_dir_xdlclose(void);") >= (int)sizeof pfx
        || snprintf(d1, sizeof d1, "void *p = dl%s(\"fixture\", 0);", "open") >= (int)sizeof d1
        || snprintf(d2, sizeof d2, "p = dl%s (h, \"fixture\");", "sym") >= (int)sizeof d2
        || snprintf(d3, sizeof d3, "(void)dl%s(h);", "close") >= (int)sizeof d3) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int rc = hs_scan_text(nested, "-", &re, nbuf, sizeof nbuf, &nused);
    if (rc == 0) rc = hs_scan_text(elseb, "-", &re, ebuf, sizeof ebuf, &eused);
    if (rc == 0) rc = hs_scan_text(inner, "-", &re, ibuf, sizeof ibuf, &iused);
    int pfx_hit = 0, direct = 0;
    const char *pl = pfx;
    while (rc == 0 && *pl) {
        const char *nl = strchr(pl, '\n');
        size_t n = nl ? (size_t)(nl - pl) : strlen(pl);
        char line[160];
        if (n >= sizeof line) { rc = 2; break; }
        memcpy(line, pl, n);
        line[n] = '\0';
        if (regexec(&re, line, 0, NULL, 0) == 0) pfx_hit++;
        pl = nl ? nl + 1 : pl + n;
        if (!nl) break;
    }
    if (rc == 0) {
        if (regexec(&re, d1, 0, NULL, 0) == 0) direct++;
        if (regexec(&re, d2, 0, NULL, 0) == 0) direct++;
        if (regexec(&re, d3, 0, NULL, 0) == 0) direct++;
    }
    int bad = rc != 0 || nused != 0 || eused == 0 || iused != 0 || pfx_hit != 0
            || direct != 3;
    if (bad)
        fputs("FAIL: hot-swap dev-region scanner selftest\n", stderr);
    regfree(&re);
    return st_ok(bad, "check_hotswap_dev_only selftest: OK\n");
}

/* check-no-api-keys: tracked-file credential shapes. Prefixes are split so
 * this translation unit is not itself a hit. */
static int nak_fill_pat(char *pat, size_t cap)
{
    return ovf(snprintf(pat, cap, "%s%s%s%s%s%s%s%s",
        "\\b" "s" "k-" "[A-Za-z0-9_-]{20,}|",
        "\\b" "x" "ai-" "[A-Za-z0-9_-]{20,}|",
        "\\b" "g" "sk_" "[A-Za-z0-9_-]{20,}|",
        "\\b" "g" "hp_" "[A-Za-z0-9_-]{20,}|",
        "\\b" "g" "lpat-" "[A-Za-z0-9_-]{20,}|",
        "\\b" "A" "KIA" "[A-Z0-9]{16}|",
        "Bearer[[:space:]]+[A-Za-z0-9._-]{24,}|",
        "[0-9a-f]{32,}\\.[A-Za-z0-9]{16,}"), cap);
}

static int nak_comp(regex_t *re)
{
    char pat[320];
    int rc = nak_fill_pat(pat, sizeof pat);
    return rc ? rc : reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int nak_skip_path(const char *path)
{
    static const char *const ext[] = {
        ".png", ".jpg", ".gz", ".xz", ".zip", ".pdf", ".ico", ".bin", ".dat"
    };
    if (!strcmp(path, "tools/lint/check_no_api_keys.sh")) return 1;
    if (!strncmp(path, "vendor/", 7)) return 1;
    if (!strncmp(path, "tests/harness/fuzz_seeds/", 25)) return 1;
    for (size_t i = 0; i < sizeof ext / sizeof ext[0]; i++)
        if (c23_ends(path, ext[i])) return 1;
    return 0;
}

static int nak_has(const char *s, size_t n, const char *needle)
{
    size_t m = strlen(needle);
    if (m == 0 || m > n) return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(s + i, needle, m) == 0) return 1;
    return 0;
}

struct nak_acc { regex_t *re; FILE *hits; int nfiles, nhits; };

static int nak_scan_file(const char *path, struct nak_acc *a)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        if (nak_has(line, (size_t)n, "api-key-example-ok")) continue;
        for (ssize_t i = 0; i < n; i++)
            if (line[i] == '\0') line[i] = ' ';
        if (n <= 0 || regexec(a->re, line, 0, NULL, 0) != 0) continue;
        a->nhits++;
        if (a->nhits > 20) continue;
        if (fprintf(a->hits, "%s:%d:", path, lineno) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)line[i];
            if (c == '\0') continue;
            if (fputc(c, a->hits) == EOF) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
        }
        if (rc) break;
        if (fputc('\n', a->hits) == EOF) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    return fin(f, line, path, rc);
}

static int nak_on_track(const char *path, void *ctx)
{
    struct nak_acc *a = ctx;
    if (nak_skip_path(path)) return 0;
    a->nfiles++;
    return nak_scan_file(path, a);
}

static int nak_scan_env(const char *env, struct nak_acc *a)
{
    const char *p = env;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        size_t n = (size_t)(p - start);
        char path[4096];
        if (n >= sizeof path)
            return die("z23-lint: path too long: %s\n", "ZCL_API_KEY_SCAN_FILES");
        memcpy(path, start, n);
        path[n] = '\0';
        a->nfiles++;
        int rc = nak_scan_file(path, a);
        if (rc) return rc;
    }
    return 0;
}

static int nak_too_few(int nfiles, int floor)
{
    if (nfiles >= floor) return 0;
    if (fprintf(stderr,
                "check_no_api_keys: FATAL — scanned %d files (floor %d).\n",
                nfiles, floor) < 0
        || fputs("check_no_api_keys: a broken scan is never reported as clean.\n",
                 stderr) < 0)
        return die("z23-lint: write failed\n", "");
    return 2;
}

static int nak_replay20(FILE *hits)
{
    if (fseek(hits, 0, SEEK_SET) != 0) return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int shown = 0, rc = 0;
    while (shown < 20 && (n = getline(&line, &cap, hits)) >= 0) {
        if (fwrite(line, 1, (size_t)n, stdout) != (size_t)n) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        shown++;
    }
    int err = ferror(hits);
    free(line);
    return rc ? rc : (err ? die("z23-lint: read failed\n", "") : 0);
}

static int nak_finish(struct nak_acc *a, int floor)
{
    int rc = nak_too_few(a->nfiles, floor);
    if (rc) return rc;
    if (a->nhits) {
        if (fputs("[check_no_api_keys] a credential-shaped string is in a tracked file:\n",
                  stdout) < 0)
            return die("z23-lint: write failed\n", "");
        rc = nak_replay20(a->hits);
        if (rc) return rc;
        if (fputs("[check_no_api_keys] a key in this tree is SPENT — it is in the history,\n"
                  "[check_no_api_keys] on every clone, and on every mirror. Rotate it, then\n"
                  "[check_no_api_keys] keep the replacement in the environment or in a 0600\n"
                  "[check_no_api_keys] file outside the repository (see engine/engine_secret.h).\n"
                  "[check_no_api_keys] For a documented non-credential, append the marker\n"
                  "[check_no_api_keys] api-key-example-ok to the line.\n", stdout) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return printf("[check_no_api_keys] 0 violation(s) across %d file(s) (mode: FAIL)\n",
                  a->nfiles) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int check_no_api_keys_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    regex_t re;
    int cr = nak_comp(&re);
    if (cr) return cr;
    FILE *hits = tmpfile();
    if (!hits) {
        regfree(&re);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct nak_acc a = { .re = &re, .hits = hits };
    const char *env = getenv("ZCL_API_KEY_SCAN_FILES");
    int floor = 1000, rc;
    if (env && env[0]) {
        floor = 1;
        rc = nak_scan_env(env, &a);
    } else {
        rc = each_zpath(k_ls_all, nak_on_track, &a);
    }
    if (rc == 0) rc = nak_finish(&a, floor);
    fclose(hits);
    regfree(&re);
    return rc;
}

static int nak_want(const regex_t *re, const char *s, int w)
{
    int got = (strstr(s, "api-key-example-ok") == NULL)
           && (regexec(re, s, 0, NULL, 0) == 0);
    if (got != w) {
        fprintf(stderr, "check_no_api_keys selftest: want %d: %s\n", w, s);
        return 1;
    }
    return 0;
}

static int check_no_api_keys_selftest(void)
{
    regex_t re;
    int cr = nak_comp(&re);
    if (cr) return cr;
    char sk[48], xai[48], gsk[48], ghp[48], glp[56], akia[40];
    char br[64], dig[80], okm[80], sha[48], shortsk[40];
    if (snprintf(sk, sizeof sk, "%s%s", "s" "k-", "abcdefghijklmnopqrst") >= (int)sizeof sk
        || snprintf(xai, sizeof xai, "%s%s", "x" "ai-", "abcdefghijklmnopqrst") >= (int)sizeof xai
        || snprintf(gsk, sizeof gsk, "%s%s", "g" "sk_", "abcdefghijklmnopqrst") >= (int)sizeof gsk
        || snprintf(ghp, sizeof ghp, "%s%s", "g" "hp_", "abcdefghijklmnopqrst") >= (int)sizeof ghp
        || snprintf(glp, sizeof glp, "%s%s", "g" "lpat-", "abcdefghijklmnopqrst") >= (int)sizeof glp
        || snprintf(akia, sizeof akia, "%s%s", "A" "KIA", "ABCDEFGHIJKLMNOP") >= (int)sizeof akia
        || snprintf(br, sizeof br, "Bearer %s", "abcdefghijklmnopqrstuvwx") >= (int)sizeof br
        || snprintf(dig, sizeof dig, "%s.%s", "0123456789abcdef0123456789abcdef",
                    "abcdefghijklmnop") >= (int)sizeof dig
        || snprintf(okm, sizeof okm, "%s api-key-example-ok", sk) >= (int)sizeof okm
        || snprintf(sha, sizeof sha, "%s",
                    "0123456789abcdef0123456789abcdef01234567") >= (int)sizeof sha
        || snprintf(shortsk, sizeof shortsk, "%s%s", "s" "k-",
                    "abcdefghijklmnopqrs") >= (int)sizeof shortsk) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int bad = nak_want(&re, sk, 1) | nak_want(&re, xai, 1) | nak_want(&re, gsk, 1)
            | nak_want(&re, ghp, 1) | nak_want(&re, glp, 1) | nak_want(&re, akia, 1)
            | nak_want(&re, br, 1) | nak_want(&re, dig, 1)
            | nak_want(&re, okm, 0) | nak_want(&re, sha, 0) | nak_want(&re, shortsk, 0)
            | nak_want(&re, "cc -std=c23 main.c", 0)
            | (nak_too_few(0, 1) != 2) | (nak_too_few(1, 1) != 0)
            | (nak_too_few(999, 1000) != 2)
            | !nak_skip_path("vendor/foo.c")
            | !nak_skip_path("tests/harness/fuzz_seeds/x.bin")
            | !nak_skip_path("docs/x.png")
            | nak_skip_path("tools/lint/lintc.c");
    regfree(&re);
    return st_ok(bad, "check_no_api_keys selftest: OK\n");
}

static int edr_skip_path(const char *path)
{
    if (!strncmp(path, "tests/harness/", 14)) return 1;
    return !(c23_ends(path, ".c") || c23_ends(path, ".h"));
}

static int edr_word(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '/' || c == '-';
}

static int edr_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static int edr_resolves(const char *tok)
{
    if (edr_exists(tok)) return 1;
    const char *base = strrchr(tok, '/');
    base = base ? base + 1 : tok;
    char p[4096];
    int n = snprintf(p, sizeof p, "docs/%s", base);
    if (ovf(n, sizeof p)) return 0;
    if (edr_exists(p)) return 1;
    n = snprintf(p, sizeof p, "docs/work/%s", base);
    if (ovf(n, sizeof p)) return 0;
    return edr_exists(p);
}

static int edr_tok_end_md(const char *tok)
{
    size_t n = strlen(tok);
    if (n < 3 || memcmp(tok + n - 3, ".md", 3) != 0) return 0;
    if (n == 3) return 0;
    if (n >= 4 && memcmp(tok + n - 4, "/.md", 4) == 0) return 0;
    return 1;
}

static int edr_lit_skip(const char *s, const char *e)
{
    for (const char *p = s; p < e; p++) {
        if (*p == '*') return 1;
        if (*p == '%' && (p + 1) < e) {
            char n = p[1];
            if (n == 's' || n == 'd' || n == 'l' || n == 'z') return 1;
        }
    }
    return 0;
}

static int edr_line(const char *file, int lineno, char *line, FILE *out, int *violations)
{
    if (!strstr(line, ".md")) return 0;
    if (strstr(line, "// error-doc-ref-ok:")) return 0;
    for (char *p = line; *p; p++) {
        if (*p != '"') continue;
        char *start = p + 1;
        char *end = start;
        while (*end && *end != '"') end++;
        if (!*end) break;
        p = end;
        int has_md = 0;
        for (char *q = start; q < end; q++)
            if (q + 2 < end && q[0] == '.' && q[1] == 'm' && q[2] == 'd') has_md = 1;
        if (!has_md || edr_lit_skip(start, end)) continue;
        char *q = start;
        while (q < end) {
            while (q < end && !edr_word((unsigned char)*q)) q++;
            if (q >= end) break;
            char *tok = q;
            while (q < end && edr_word((unsigned char)*q)) q++;
            char saved = *q;
            *q = '\0';
            if (edr_tok_end_md(tok) && !edr_resolves(tok)) {
                (*violations)++;
                if (out && fprintf(out, "  %s:%d names a document that does not exist: %s\n",
                                   file, lineno, tok) < 0) {
                    *q = saved;
                    return die("z23-lint: write failed\n", "");
                }
            }
            *q = saved;
        }
    }
    return 0;
}

static int edr_scan_file(const char *path, int *violations)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        rc = edr_line(path, lineno, line, stdout, violations);
        if (rc) break;
    }
    return fin(f, line, path, rc);
}

static int edr_on_track(const char *path, void *ctx)
{
    int *violations = ctx;
    if (edr_skip_path(path)) return 0;
    return edr_scan_file(path, violations);
}

static int edr_fail(int n)
{
    if (printf("\ncheck_error_doc_refs: FAIL — %d operator-facing reference(s) to a missing document\n"
               "\n"
               "An error message that names a document the reader cannot open is worse\n"
               "than one that names nothing: it spends a round trip and it costs the\n"
               "error surface its credibility. Either write the document, or replace the\n"
               "reference with a command you have actually run.\n"
               "\n"
               "If the path is genuinely produced at runtime, append\n"
               "  // error-doc-ref-ok:<reason>\n"
               "to the line.\n", n) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int check_error_doc_refs_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int violations = 0;
    int rc = each_zpath(k_ls_all, edr_on_track, &violations);
    if (rc) return rc;
    if (violations) return edr_fail(violations);
    return fputs("check_error_doc_refs: clean — every document named in a C string literal exists\n",
                 stdout) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int check_error_doc_refs_selftest(void)
{
    char real[] = "const char *p = \"AGENTS.md\";";
    char miss[] = "const char *p = \"lintc11-no-such.md\";";
    char conv[] = "const char *p = \"lintc11-no-such-%s.md\";";
    char mark[] = "const char *p = \"lintc11-no-such.md\"; // error-doc-ref-ok:runtime";
    char docs[] = "const char *p = \"GETTING_STARTED.md\";";
    int v = 0, bad = 0;
    FILE *out = tmpfile();
    if (!out) return die("z23-lint: tmpfile failed\n", "");
    bad |= edr_line("tools/t.c", 1, real, out, &v) != 0 || v != 0;
    v = 0;
    bad |= edr_line("tools/t.c", 3, miss, out, &v) != 0 || v != 1;
    v = 0;
    bad |= edr_line("tools/t.c", 4, conv, out, &v) != 0 || v != 0;
    v = 0;
    bad |= edr_line("tools/t.c", 5, mark, out, &v) != 0 || v != 0;
    v = 0;
    bad |= edr_line("tools/t.c", 6, docs, out, &v) != 0 || v != 0;
    bad |= !edr_skip_path("tests/harness/foo.c")
        || !edr_skip_path("tests/harness/include/test/x.h")
        || edr_skip_path("tools/t.c")
        || !edr_skip_path("docs/x." "md");
    fclose(out);
    if (bad)
        fputs("FAIL: check_error_doc_refs selftest\n", stderr);
    return st_ok(bad, "check_error_doc_refs selftest: OK\n");
}

static const char k_csr_mirror[] =
    "engine/modules/hotswap/include/hotswap/core_seal_root.h";
static const char k_csr_mod[] =
    "engine/modules/hotswap/include/hotswap/hotswap_module.h";
static const char k_csr_act[] = "engine/modules/hotswap/src/hotswap_activate.c";
static const char k_csr_gen[] = "tools/scripts/gen_core_seal_root.sh";

static int csr_note(FILE *out, const char *msg)
{
    return fprintf(out, "  %s\n", msg) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int csr_bad(FILE *err, int *fail, const char *msg)
{
    *fail = 1;
    return fprintf(err, "core_seal_root_mirror: FAIL — %s\n", msg) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int csr_readable(const char *path)
{
    return access(path, R_OK) == 0;
}

static int capture_cmd(const char *cmd, char *out, size_t cap, int *code)
{
    FILE *p = popen(cmd, "r");
    if (!p)
        return die("z23-lint: popen failed (%s)\n", cmd);
    size_t used = 0;
    out[0] = '\0';
    int rc = 0;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0) {
        if (used + n >= cap) {
            rc = die("z23-lint: derived buffer overflow\n", "");
            break;
        }
        memcpy(out + used, buf, n);
        used += n;
        out[used] = '\0';
    }
    if (rc == 0 && ferror(p))
        rc = die("z23-lint: read failed (%s)\n", cmd);
    int st = pclose(p);
    if (rc)
        return rc;
    while (used && out[used - 1] == '\n')
        out[--used] = '\0';
    if (st == -1)
        *code = 127;
    else if (WIFEXITED(st))
        *code = WEXITSTATUS(st);
    else
        *code = 127;
    return 0;
}

static int csr_file_pred(const char *path, int (*pred)(const char *), int *found)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        *found = 0;
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *found = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (pred(line)) {
            *found = 1;
            break;
        }
    }
    return fin(f, line, path, rc);
}

static int csr_has_include(const char *line)
{
    static const char p[] = "#include \"" "hotswap/core_seal_root.h" "\"";
    return strncmp(line, p, sizeof p - 1) == 0;
}

static int csr_has_pin(const char *line)
{
    return strstr(line, "zcl_hotswap_module_core_seal_root" "[] = "
                        "ZCL_CORE_SEAL_ROOT;") != NULL;
}

static int csr_count_sub(const char *path, const char *needle, int *count)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        *count = 0;
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *count = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        for (ssize_t i = 0; i < n; i++)
            if (line[i] == '\0')
                line[i] = ' ';
        if (strstr(line, needle))
            (*count)++;
    }
    return fin(f, line, path, rc);
}

static int csr_count_re(const char *path, const regex_t *re, int *count)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        *count = 0;
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *count = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        for (ssize_t i = 0; i < n; i++)
            if (line[i] == '\0')
                line[i] = ' ';
        if (regexec(re, line, 0, NULL, 0) == 0)
            (*count)++;
    }
    return fin(f, line, path, rc);
}

static int csr_comp_dlsym(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED,
                       "dl" "sym\\(handle,($|[[:space:]]",
                       "ZCL_HOTSWAP_MODULE_SYMBOL\\))", "", "");
}

static int csr_footer(FILE *err)
{
    if (fputs("core_seal_root_mirror: the hot-swap consensus pin is broken.\n", err) < 0
        || fputs("  A module built against a different sealed consensus core carries its own\n",
                 err) < 0
        || fputs("  stale copy of the inline consensus arithmetic. The pin is what refuses it.\n",
                 err) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int csr_check(FILE *out, FILE *err)
{
    static const char *const files[] = {
        k_csr_mirror, k_csr_mod, k_csr_act, k_csr_gen
    };
    int fail = 0, rc = 0;
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        if (csr_readable(files[i]))
            continue;
        char msg[4096];
        if (ovf(snprintf(msg, sizeof msg, "%s is missing or unreadable", files[i]),
                sizeof msg))
            return 2;
        rc = csr_bad(err, &fail, msg);
        if (rc)
            return rc;
    }
    if (fail)
        return 1;

    char cmd[256], genout[8192], msg[4096], note[8192];
    if (ovf(snprintf(cmd, sizeof cmd, "bash %s --check 2>&1", k_csr_gen), sizeof cmd))
        return 2;
    int code = 0;
    rc = capture_cmd(cmd, genout, sizeof genout, &code);
    if (rc)
        return rc;
    if (code == 0) {
        const char pfx[] = "core_seal_root: ";
        const char *rest = strncmp(genout, pfx, sizeof pfx - 1) == 0
                               ? genout + (sizeof pfx - 1) : genout;
        if (ovf(snprintf(note, sizeof note, "current  : %s", rest), sizeof note))
            return 2;
        rc = csr_note(out, note);
        if (rc)
            return rc;
    } else {
        if (fprintf(err, "%s\n", genout) < 0)
            return die("z23-lint: write failed\n", "");
        rc = csr_bad(err, &fail,
                     "the mirror does not match core/MANIFEST.sha3 (run 'make core-seal')");
        if (rc)
            return rc;
    }

    int found = 0;
    rc = csr_file_pred(k_csr_mod, csr_has_include, &found);
    if (rc)
        return rc;
    if (found) {
        if (ovf(snprintf(note, sizeof note, "exported : %s includes the mirror", k_csr_mod),
                sizeof note))
            return 2;
        rc = csr_note(out, note);
        if (rc)
            return rc;
    } else {
        if (ovf(snprintf(msg, sizeof msg,
                         "%s does not include \"hotswap/core_seal_root.h\" — "
                         "modules would compile without a pin", k_csr_mod),
                sizeof msg))
            return 2;
        rc = csr_bad(err, &fail, msg);
        if (rc)
            return rc;
    }

    rc = csr_file_pred(k_csr_mod, csr_has_pin, &found);
    if (rc)
        return rc;
    if (found) {
        rc = csr_note(out, "exported : the module emitter stamps the pin symbol");
        if (rc)
            return rc;
    } else {
        if (ovf(snprintf(msg, sizeof msg,
                         "%s's ZCL_HOTSWAP_MODULE_LEAVES does not emit "
                         "zcl_hotswap_module_core_seal_root", k_csr_mod),
                sizeof msg))
            return 2;
        rc = csr_bad(err, &fail, msg);
        if (rc)
            return rc;
    }

    int enforced = 0;
    rc = csr_count_sub(k_csr_act, "module_consensus_pin_ok(", &enforced);
    if (rc)
        return rc;
    if (enforced >= 3) {
        if (ovf(snprintf(note, sizeof note,
                         "enforced : %s checks the pin on %d dlsym path(s)",
                         k_csr_act, enforced - 1),
                sizeof note))
            return 2;
        rc = csr_note(out, note);
        if (rc)
            return rc;
    } else {
        if (ovf(snprintf(msg, sizeof msg,
                         "%s has %d module_consensus_pin_ok reference(s); "
                         "expected a definition plus a call on BOTH dlsym paths",
                         k_csr_act, enforced),
                sizeof msg))
            return 2;
        rc = csr_bad(err, &fail, msg);
        if (rc)
            return rc;
    }

    regex_t dlre;
    rc = csr_comp_dlsym(&dlre);
    if (rc)
        return rc;
    int sites = 0;
    rc = csr_count_re(k_csr_act, &dlre, &sites);
    regfree(&dlre);
    if (rc)
        return rc;
    if (sites != enforced - 1) {
        if (ovf(snprintf(msg, sizeof msg,
                         "%s resolves %d zcl_hotswap_module symbol(s) but pins %d; "
                         "every dlsym path must carry the check",
                         k_csr_act, sites, enforced - 1),
                sizeof msg))
            return 2;
        rc = csr_bad(err, &fail, msg);
        if (rc)
            return rc;
    }

    if (fail)
        return csr_footer(err);
    return fputs("core_seal_root_mirror: OK — pin current, exported by the module "
                 "emitter, enforced on every dlsym path\n", out) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int check_core_seal_root_mirror_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return csr_check(stdout, stderr);
}

static int csr_mkdirs(const char *path)
{
    char buf[4096];
    if (ovf(snprintf(buf, sizeof buf, "%s", path), sizeof buf))
        return 2;
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return die("z23-lint: mkdir failed: %s\n", buf);
        *p = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST)
        return die("z23-lint: mkdir failed: %s\n", buf);
    return 0;
}

static int csr_write(const char *path, const char *text)
{
    char dir[4096];
    const char *slash = strrchr(path, '/');
    if (!slash)
        return die("z23-lint: path too long: %s\n", path);
    size_t n = (size_t)(slash - path);
    if (n >= sizeof dir)
        return die("z23-lint: path too long: %s\n", path);
    memcpy(dir, path, n);
    dir[n] = '\0';
    int rc = csr_mkdirs(dir);
    if (rc)
        return rc;
    FILE *f = fopen(path, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    size_t len = strlen(text);
    rc = fwrite(text, 1, len, f) != len;
    if (fclose(f) != 0 && rc == 0)
        return die("z23-lint: fclose failed: %s\n", path);
    return rc ? die("z23-lint: write failed\n", "") : 0;
}

static int csr_slurp(FILE *f, char *buf, size_t cap)
{
    rewind(f);
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    return ferror(f) ? die("z23-lint: read failed\n", "") : 0;
}

static int csr_plant_act(const char *path)
{
    char body[512];
    int n = snprintf(body, sizeof body,
                     "static bool module_consensus_pin_ok(void *h) { (void)h; return 1; }\n"
                     "void mount(void *handle) {\n"
                     "    (void)dl" "sym(handle, ZCL_HOTSWAP_MODULE_SYMBOL);\n"
                     "    module_consensus_pin_ok(handle);\n"
                     "}\n"
                     "void verify(void *handle) {\n"
                     "    (void)dl" "sym(handle,\n"
                     "    module_consensus_pin_ok(handle);\n"
                     "}\n");
    if (ovf(n, sizeof body))
        return 2;
    return csr_write(path, body);
}

static int csr_plant_mod(const char *path, int with_include)
{
    char body[256];
    int n;
    if (with_include)
        n = snprintf(body, sizeof body,
                     "#include \"" "hotswap/core_seal_root.h" "\"\n"
                     "const char zcl_hotswap_module_core_seal_root" "[] = "
                     "ZCL_CORE_SEAL_ROOT;\n");
    else
        n = snprintf(body, sizeof body,
                     "const char zcl_hotswap_module_core_seal_root" "[] = "
                     "ZCL_CORE_SEAL_ROOT;\n");
    if (ovf(n, sizeof body))
        return 2;
    return csr_write(path, body);
}

static int csr_plant_base(void)
{
    int rc = csr_write(k_csr_mirror, "/* fixture mirror */\n");
    if (rc == 0)
        rc = csr_plant_act(k_csr_act);
    if (rc == 0)
        rc = csr_write(k_csr_gen, "echo \"core_seal_root: OK — fixture\"\nexit 0\n");
    return rc;
}

static int check_core_seal_root_mirror_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-csr-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char ob[4096], eb[4096];
    int bad = 0, rc = 0;
    if (chdir(root) != 0) {
        fclose(out); fclose(err); rmdir(root);
        return die("z23-lint: cannot scan %s\n", root);
    }

    rc = csr_check(out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, eb, sizeof eb))
        bad = 1;
    bad |= rc != 1
        || strstr(eb, "core_seal_root_mirror: FAIL — ") == NULL
        || strstr(eb, " is missing or unreadable") == NULL;

    rewind(out); rewind(err);
    if (ftruncate(fileno(out), 0) != 0 || ftruncate(fileno(err), 0) != 0)
        bad = 1;

    if (csr_plant_base() || csr_plant_mod(k_csr_mod, 0))
        bad = 1;
    rc = csr_check(out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, eb, sizeof eb))
        bad = 1;
    bad |= rc != 1
        || strstr(eb, "does not include \"hotswap/core_seal_root.h\"") == NULL;

    rewind(out); rewind(err);
    if (ftruncate(fileno(out), 0) != 0 || ftruncate(fileno(err), 0) != 0)
        bad = 1;
    if (csr_plant_mod(k_csr_mod, 1))
        bad = 1;
    rc = csr_check(out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, eb, sizeof eb))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "core_seal_root_mirror: OK — pin current, exported by the "
                      "module emitter, enforced on every dlsym path") == NULL;

    fclose(out);
    fclose(err);
    unlink(k_csr_mirror);
    unlink(k_csr_mod);
    unlink(k_csr_act);
    unlink(k_csr_gen);
    (void)rmdir("engine/modules/hotswap/include/hotswap");
    (void)rmdir("engine/modules/hotswap/include");
    (void)rmdir("engine/modules/hotswap/src");
    (void)rmdir("engine/modules/hotswap");
    (void)rmdir("engine/modules");
    (void)rmdir("engine");
    (void)rmdir("tools/scripts");
    (void)rmdir("tools");
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_core_seal_root_mirror selftest\n", stderr);
    return st_ok(bad, "check_core_seal_root_mirror selftest: OK\n");
}

static const char k_pf_hdr[] = "core/modules/net/include/net/net.h";
static const char *const k_pf_sites[] = {
    "core/modules/net/src/connman.c",
    "engine/supervisors/src/net_supervisor.c",
    "engine/conditions/src/peer_floor_violated.c",
};
static const char *const k_pf_walk_roots[] = {
    "lib", "app", "config", "core", "domain", "tools"
};

static int pf_comp_banned(regex_t *re)
{
    char pat[256];
    int n = snprintf(pat, sizeof pat, "%s%s%s%s",
                     "^[[:space:]]*#[[:space:]]*define[[:space:]]+(",
                     "PEER_FLOOR_MIN|PEER_FLOOR_MIN_HEALTHY|",
                     "PEER_FLOOR_TARGET|OUTBOUND_HEALTHY_FLOOR)",
                     "[[:space:]]+[0-9]");
    if (ovf(n, sizeof pat))
        return 2;
    return reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int pf_comp_def(regex_t *re)
{
    char pat[160];
    int n = snprintf(pat, sizeof pat, "%s%s%s",
                     "^[[:space:]]*#[[:space:]]*define[[:space:]]+",
                     "ZCL_" "PEER_FLOOR_HEALTHY",
                     "[[:space:]]+[0-9]");
    if (ovf(n, sizeof pat))
        return 2;
    return reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int pf_comp_ref(regex_t *re)
{
    char pat[160];
    int n = snprintf(pat, sizeof pat, "%s%s%s",
                     "(^|[^[:alnum:]_])",
                     "ZCL_" "PEER_FLOOR_HEALTHY",
                     "([^[:alnum:]_]|$)");
    if (ovf(n, sizeof pat))
        return 2;
    return reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int pf_count_re(const char *path, const regex_t *re, int *count)
{
    return csr_count_re(path, re, count);
}

static int pf_file_has_re(const char *path, const regex_t *re)
{
    int n = 0;
    if (pf_count_re(path, re, &n))
        return 0;
    return n > 0;
}

enum { PF_MAX = 128, PF_NAME = 256 };
struct pf_tree { char p[PF_MAX][PF_NAME]; int n; const regex_t *re; };

static int pf_path_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int pf_add(struct pf_tree *t, const char *path)
{
    size_t n = strlen(path);
    if (t->n >= PF_MAX || n >= PF_NAME)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(t->p[t->n], path, n + 1);
    t->n++;
    return 0;
}

static int pf_walk(const char *dir, struct pf_tree *t)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return 0;
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = 0;
            else if (S_ISDIR(st.st_mode))
                rc = pf_walk(path, t);
            else if (S_ISREG(st.st_mode) && pf_file_has_re(path, t->re))
                rc = pf_add(t, path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int pf_is_reg(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int pf_selftest_mode(const char *f, FILE *out, FILE *err)
{
    if (!f || !f[0] || !pf_is_reg(f)) {
        if (fprintf(err,
                    "check_peer_floor_single_source: FATAL — selftest file missing: '%s'\n",
                    f ? f : "") < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    regex_t re;
    int cr = pf_comp_banned(&re);
    if (cr)
        return cr;
    int hit = pf_file_has_re(f, &re);
    regfree(&re);
    if (hit) {
        if (fprintf(out,
                    "check_peer_floor_single_source: selftest TRIP — banned floor literal in %s\n",
                    f) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (fprintf(out,
                "check_peer_floor_single_source: selftest CLEAN — no banned floor literal in %s\n",
                f) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int pf_scan_banned_lines(const char *path, const regex_t *re, FILE *err)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0, any = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        for (ssize_t i = 0; i < n; i++)
            if (line[i] == '\0')
                line[i] = ' ';
        if (regexec(re, line, 0, NULL, 0) != 0)
            continue;
        if (!any) {
            if (fprintf(err,
                        "check_peer_floor_single_source: FAIL — %s reintroduces a "
                        "retired floor literal macro:\n", path) < 0) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
            any = 1;
        }
        if (fprintf(err, "    %d:%s\n", lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    int fr = fin(f, line, path, rc);
    if (fr)
        return fr;
    if (any) {
        if (fprintf(err, "    Use ZCL_" "PEER_FLOOR_HEALTHY from %s instead.\n",
                    k_pf_hdr) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return 0;
}

static int check_peer_floor_single_source_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *st = getenv("ZCL_PEER_FLOOR_SELFTEST");
    if (st && strcmp(st, "1") == 0)
        return pf_selftest_mode(getenv("ZCL_PEER_FLOOR_SELFTEST_FILE"),
                                stdout, stderr);

    if (!pf_is_reg(k_pf_hdr)) {
        fprintf(stderr,
                "check_peer_floor_single_source: FATAL — expected file missing: %s\n",
                k_pf_hdr);
        return 2;
    }
    for (size_t i = 0; i < sizeof k_pf_sites / sizeof k_pf_sites[0]; i++) {
        if (pf_is_reg(k_pf_sites[i]))
            continue;
        fprintf(stderr,
                "check_peer_floor_single_source: FATAL — expected file missing: %s\n",
                k_pf_sites[i]);
        return 2;
    }

    regex_t def, ref, banned;
    int cr = pf_comp_def(&def);
    if (cr)
        return cr;
    cr = pf_comp_ref(&ref);
    if (cr) {
        regfree(&def);
        return cr;
    }
    cr = pf_comp_banned(&banned);
    if (cr) {
        drop2(&def, &ref);
        return cr;
    }

    int fail = 0, def_count = 0, rc = pf_count_re(k_pf_hdr, &def, &def_count);
    if (rc) {
        drop3(&def, &ref, &banned);
        return rc;
    }
    if (def_count != 1) {
        if (fprintf(stderr,
                    "check_peer_floor_single_source: FAIL — ZCL_"
                    "PEER_FLOOR_HEALTHY must be #define'd exactly once (as a number) "
                    "in %s (found %d)\n", k_pf_hdr, def_count) < 0) {
            drop3(&def, &ref, &banned);
            return die("z23-lint: write failed\n", "");
        }
        fail = 1;
    }

    struct pf_tree tree = { .re = &def };
    for (size_t i = 0; rc == 0 && i < sizeof k_pf_walk_roots / sizeof k_pf_walk_roots[0]; i++)
        rc = pf_walk(k_pf_walk_roots[i], &tree);
    if (rc) {
        drop3(&def, &ref, &banned);
        return rc;
    }
    if (tree.n > 1)
        qsort(tree.p, (size_t)tree.n, sizeof tree.p[0], pf_path_cmp);
    int uniq = 0;
    for (int i = 0; i < tree.n; i++) {
        if (i && strcmp(tree.p[i], tree.p[i - 1]) == 0)
            continue;
        if (uniq != i)
            memcpy(tree.p[uniq], tree.p[i], PF_NAME);
        uniq++;
    }
    tree.n = uniq;
    if (tree.n != 1) {
        if (fprintf(stderr,
                    "check_peer_floor_single_source: FAIL — ZCL_"
                    "PEER_FLOOR_HEALTHY defined in %d files (expected 1):\n",
                    tree.n) < 0) {
            drop3(&def, &ref, &banned);
            return die("z23-lint: write failed\n", "");
        }
        if (tree.n == 0) {
            if (fputs("    \n", stderr) < 0) {
                drop3(&def, &ref, &banned);
                return die("z23-lint: write failed\n", "");
            }
        } else {
            for (int i = 0; i < tree.n; i++) {
                if (fprintf(stderr, "    %s\n", tree.p[i]) < 0) {
                    drop3(&def, &ref, &banned);
                    return die("z23-lint: write failed\n", "");
                }
            }
        }
        fail = 1;
    }

    int total_refs = 0;
    for (size_t i = 0; i < sizeof k_pf_sites / sizeof k_pf_sites[0]; i++) {
        int refs = 0;
        rc = pf_count_re(k_pf_sites[i], &ref, &refs);
        if (rc) {
            drop3(&def, &ref, &banned);
            return rc;
        }
        total_refs += refs;
        if (refs < 1) {
            if (fprintf(stderr,
                        "check_peer_floor_single_source: FAIL — %s does not reference "
                        "ZCL_" "PEER_FLOOR_HEALTHY (re-hardcoded floor?)\n",
                        k_pf_sites[i]) < 0) {
                drop3(&def, &ref, &banned);
                return die("z23-lint: write failed\n", "");
            }
            fail = 1;
        }
        int br = pf_scan_banned_lines(k_pf_sites[i], &banned, stderr);
        if (br == 2) {
            drop3(&def, &ref, &banned);
            return 2;
        }
        if (br == 1)
            fail = 1;
    }
    drop3(&def, &ref, &banned);

    if (total_refs < 1) {
        fputs("check_peer_floor_single_source: FATAL — zero ZCL_"
              "PEER_FLOOR_HEALTHY references across all floor sites; the wiring "
              "drifted (refusing to report clean)\n", stderr);
        return 2;
    }
    if (fail) {
        fputs("check_peer_floor_single_source: the healthy-outbound floor has "
              "drifted from its single source of truth.\n", stderr);
        return 1;
    }
    return printf("[check_peer_floor_single_source] OK — ZCL_"
                  "PEER_FLOOR_HEALTHY defined once in %s and read by all %d floor "
                  "references across %zu sites\n",
                  k_pf_hdr, total_refs,
                  sizeof k_pf_sites / sizeof k_pf_sites[0]) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int check_peer_floor_single_source_selftest(void)
{
    char tmpl[] = "/tmp/z23-lint-pf-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    char miss[64], trip[256], clean[256], ob[512], eb[512];
    int n = snprintf(trip, sizeof trip, "%s/trip.c", root);
    if (ovf(n, sizeof trip))
        return 2;
    n = snprintf(clean, sizeof clean, "%s/clean.c", root);
    if (ovf(n, sizeof clean))
        return 2;
    FILE *tf = fopen(trip, "w"), *cf = fopen(clean, "w");
    if (!tf || !cf) {
        if (tf) fclose(tf);
        if (cf) fclose(cf);
        rmdir(root);
        return die("z23-lint: cannot open %s\n", root);
    }
    fputs("#define PEER_FLOOR_MIN 3\n", tf);
    fputs("int x = ZCL_" "PEER_FLOOR_HEALTHY;\n", cf);
    fclose(tf);
    fclose(cf);

    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        unlink(trip); unlink(clean); rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    int bad = 0;
    miss[0] = '\0';
    int rc = pf_selftest_mode(miss, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, eb, sizeof eb))
        bad = 1;
    bad |= rc != 2
        || strstr(eb, "check_peer_floor_single_source: FATAL — selftest file missing: ''") == NULL;

    rewind(out); rewind(err);
    if (ftruncate(fileno(out), 0) != 0 || ftruncate(fileno(err), 0) != 0)
        bad = 1;
    rc = pf_selftest_mode(trip, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, eb, sizeof eb))
        bad = 1;
    bad |= rc != 1 || strstr(ob, "selftest TRIP — banned floor literal in ") == NULL
        || strstr(ob, trip) == NULL;

    rewind(out); rewind(err);
    if (ftruncate(fileno(out), 0) != 0 || ftruncate(fileno(err), 0) != 0)
        bad = 1;
    rc = pf_selftest_mode(clean, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, eb, sizeof eb))
        bad = 1;
    bad |= rc != 0 || strstr(ob, "selftest CLEAN — no banned floor literal in ") == NULL
        || strstr(ob, clean) == NULL;

    fclose(out);
    fclose(err);
    unlink(trip);
    unlink(clean);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_peer_floor_single_source selftest\n", stderr);
    return st_ok(bad, "check_peer_floor_single_source selftest: OK\n");
}

static const char k_psp_pin[] = "tools/scripts/proof_server_pin.sh";
static const char k_psp_ship[] = "tools/ship.sh";

static int psp_has_pass_line(const char *buf)
{
    static const char want[] = "PROOF SERVER PIN SELF-TEST: PASS";
    size_t w = sizeof want - 1;
    const char *p = buf;
    for (;;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n == w && memcmp(p, want, w) == 0)
            return 1;
        if (!nl)
            return 0;
        p = nl + 1;
    }
}

static int psp_file_has_record(const char *path, int *has)
{
    regex_t re;
    int cr = compile_pat(&re, REG_EXTENDED,
                        "proof_server_pin" "\\.sh[[:space:]]+",
                        "record", "([^[:alnum:]_]|$)", "");
    if (cr)
        return cr;
    FILE *f = fopen(path, "r");
    if (!f) {
        *has = 0;
        regfree(&re);
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *has = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (regexec(&re, line, 0, NULL, 0) == 0) {
            *has = 1;
            break;
        }
    }
    rc = fin(f, line, path, rc);
    regfree(&re);
    return rc;
}

static int psp_check(FILE *out)
{
    int fail = 0, rc;
    if (!csr_readable(k_psp_pin)) {
        if (fprintf(out,
                    "FAIL: %s is missing — the proof-server promotion has no recorder\n",
                    k_psp_pin) < 0)
            return die("z23-lint: write failed\n", "");
        fail = 1;
    } else {
        char cmd[256], captured[8192];
        if (ovf(snprintf(cmd, sizeof cmd, "bash %s --self-test 2>&1", k_psp_pin),
                sizeof cmd))
            return 2;
        int code = 0;
        rc = capture_cmd(cmd, captured, sizeof captured, &code);
        if (rc)
            return rc;
        if (code != 0 || !psp_has_pass_line(captured)) {
            if (fprintf(out,
                        "FAIL: %s --self-test (rc=%d; no 'PROOF SERVER PIN SELF-TEST: PASS' line)\n",
                        k_psp_pin, code) < 0)
                return die("z23-lint: write failed\n", "");
            if (fprintf(out, "%s\n", captured) < 0)
                return die("z23-lint: write failed\n", "");
            fail = 1;
        } else if (fprintf(out, "  ok: %s --self-test\n", k_psp_pin) < 0) {
            return die("z23-lint: write failed\n", "");
        }
    }

    if (!csr_readable(k_psp_ship)) {
        if (fprintf(out, "FAIL: %s is missing\n", k_psp_ship) < 0)
            return die("z23-lint: write failed\n", "");
        fail = 1;
    } else {
        int has = 0;
        rc = psp_file_has_record(k_psp_ship, &has);
        if (rc)
            return rc;
        if (!has) {
            if (fputs("FAIL: tools/ship.sh no longer calls 'proof_server_pin.sh record' — the\n"
                      "      promotion path would go back to describing a binding it does\n"
                      "      not record. Wire the call back in after the remote health\n"
                      "      check confirms the running daemon reports the candidate's\n"
                      "      source id.\n", out) < 0)
                return die("z23-lint: write failed\n", "");
            fail = 1;
        } else if (fprintf(out, "  ok: %s calls 'proof_server_pin.sh record'\n",
                           k_psp_ship) < 0) {
            return die("z23-lint: write failed\n", "");
        }
    }
    if (fail)
        return 1;
    return fputs("check_proof_server_pin: clean — recorder self-test passes and "
                 "ship.sh still wires it into the promotion path\n", out) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int check_proof_server_pin_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return psp_check(stdout);
}

static int psp_st_reset(FILE *out)
{
    rewind(out);
    return ftruncate(fileno(out), 0) != 0;
}

static int check_proof_server_pin_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-psp-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile();
    if (!out) {
        rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char ob[4096];
    int bad = 0, rc = 0;
    if (chdir(root) != 0) {
        fclose(out);
        rmdir(root);
        return die("z23-lint: cannot scan %s\n", root);
    }

    rc = psp_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: tools/scripts/proof_server_pin.sh is missing — "
                      "the proof-server promotion has no recorder") == NULL;

    if (psp_st_reset(out))
        bad = 1;
    if (csr_write(k_psp_pin, "echo PROOF SERVER PIN SELF-TEST: PASS\n")
        || csr_write(k_psp_ship,
                     "# mention record elsewhere\n"
                     "tools/scripts/proof_server_pin.sh check\n"))
        bad = 1;
    rc = psp_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: tools/ship.sh no longer calls "
                      "'proof_server_pin.sh record' — the") == NULL;

    if (psp_st_reset(out))
        bad = 1;
    if (csr_write(k_psp_ship,
                  "tools/scripts/proof_server_pin.sh record \"$HEAD_SHA\"\n"))
        bad = 1;
    rc = psp_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check_proof_server_pin: clean — recorder self-test "
                      "passes and ship.sh still wires it into the promotion "
                      "path") == NULL;

    fclose(out);
    unlink(k_psp_pin);
    unlink(k_psp_ship);
    (void)rmdir("tools/scripts");
    (void)rmdir("tools");
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_proof_server_pin selftest\n", stderr);
    return st_ok(bad, "check_proof_server_pin selftest: OK\n");
}

static int trs_on_recipe(FILE *out, int cov, int start, const char *argv,
                         int *dep_total, int *dep_seeded, int *cov_total,
                         int *fail)
{
    static const char needle[] = "$(" "ZCL_TU_RANDOM_SEED" ")";
    int has = strstr(argv, needle) != NULL;
    if (!cov) {
        (*dep_total)++;
        if (has) {
            (*dep_seeded)++;
            return 0;
        }
        if (fprintf(out,
                    "FAIL: Makefile:%d — per-TU object recipe does not carry $("
                    "ZCL_TU_RANDOM_SEED)\n", start) < 0)
            return die("z23-lint: write failed\n", "");
        if (fprintf(out, "      %s\n", argv) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
        return 0;
    }
    (*cov_total)++;
    if (!has)
        return 0;
    if (fprintf(out,
                "FAIL: Makefile:%d — the coverage recipe carries $("
                "ZCL_TU_RANDOM_SEED).\n", start) < 0)
        return die("z23-lint: write failed\n", "");
    if (fputs("      Coverage is the documented exemption (gcno/gcda pairing).\n"
              "      If that changed, update this gate and the reason with it.\n",
              out) < 0)
        return die("z23-lint: write failed\n", "");
    *fail = 1;
    return 0;
}

/* The original gate piped Makefile lines through a bash command
 * substitution ($(awk ...) / $(grep ...)), and bash silently drops any
 * embedded NUL byte from that captured text rather than truncating at it.
 * getline() keeps the NUL as a literal byte, so strstr()/regexec() on the
 * raw buffer would stop early instead — a divergence from the original's
 * behavior. Squeeze NULs out (and drop the trailing newline) so a line
 * with an embedded NUL is judged on the same reassembled text the original
 * bash pipeline saw. */
static ssize_t trs_squeeze_line(char *buf, ssize_t n)
{
    if (n > 0 && buf[n - 1] == '\n')
        n--;
    ssize_t w = 0;
    for (ssize_t r = 0; r < n; r++) {
        if (buf[r] != '\0')
            buf[w++] = buf[r];
    }
    buf[w] = '\0';
    return w;
}

static int trs_check(FILE *out)
{
    regex_t seedre, trig, covre, cont;
    int cr = compile_pat(&seedre, REG_EXTENDED,
                        "^ZCL_TU_" "RANDOM_SEED[[:space:]]*=", "", "", "");
    if (cr)
        return cr;
    cr = compile_pat(&trig, REG_EXTENDED,
                     "BUILD_(EPOCH_OBJECT_TOOL|FAST_EPOCH_OBJECT_COMMAND)\\)"
                     "[[:space:]]+(dep|coverage)[[:space:]]",
                     "", "", "");
    if (cr) {
        regfree(&seedre);
        return cr;
    }
    cr = compile_pat(&covre, REG_EXTENDED, "[[:space:]]coverage[[:space:]]",
                     "", "", "");
    if (cr) {
        drop2(&seedre, &trig);
        return cr;
    }
    cr = compile_pat(&cont, REG_EXTENDED, "\\\\[[:space:]]*$", "", "", "");
    if (cr) {
        drop3(&seedre, &trig, &covre);
        return cr;
    }

    FILE *f = fopen("Makefile", "r");
    char seed_def[4096];
    seed_def[0] = '\0';
    int found_seed = 0;
    if (f) {
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        size_t used = 0;
        int rc = 0;
        while ((n = getline(&line, &cap, f)) >= 0) {
            n = trs_squeeze_line(line, n);
            if (regexec(&seedre, line, 0, NULL, 0) != 0)
                continue;
            size_t ln = strlen(line);
            if (found_seed) {
                if (used + 1 >= sizeof seed_def) {
                    rc = die("z23-lint: derived buffer overflow\n", "");
                    break;
                }
                seed_def[used++] = '\n';
                seed_def[used] = '\0';
            }
            if (used + ln >= sizeof seed_def) {
                rc = die("z23-lint: derived buffer overflow\n", "");
                break;
            }
            memcpy(seed_def + used, line, ln + 1);
            used += ln;
            found_seed = 1;
        }
        int fr = fin(f, line, "Makefile", rc);
        if (fr) {
            drop3(&seedre, &trig, &covre);
            regfree(&cont);
            return fr;
        }
    }
    if (!found_seed) {
        drop3(&seedre, &trig, &covre);
        regfree(&cont);
        if (fputs("FAIL: Makefile does not define ZCL_TU_RANDOM_SEED\n", out) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    const char *frs = strstr(seed_def, "-" "frandom-seed=");
    if (!frs || !strstr(frs, "$<")) {
        drop3(&seedre, &trig, &covre);
        regfree(&cont);
        if (fputs("FAIL: ZCL_TU_RANDOM_SEED must expand to -frandom-seed=<per-TU value>.\n"
                  "      A seed that is the same for every TU is not a per-TU seed.\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        if (fprintf(out, "      Found: %s\n", seed_def) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }

    f = fopen("Makefile", "r");
    if (!f) {
        drop3(&seedre, &trig, &covre);
        regfree(&cont);
        if (fputs("FAIL: found no compile-epoch-object.sh object recipes in Makefile\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0, found = 0, fail = 0;
    int dep_total = 0, dep_seeded = 0, cov_total = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        n = trs_squeeze_line(line, n);
        if (regexec(&trig, line, 0, NULL, 0) != 0)
            continue;
        found = 1;
        int cov = regexec(&covre, line, 0, NULL, 0) == 0;
        int start = lineno;
        while (regexec(&cont, line, 0, NULL, 0) == 0) {
            n = getline(&line, &cap, f);
            if (n < 0)
                break;
            lineno++;
            n = trs_squeeze_line(line, n);
        }
        if (n < 0 && ferror(f)) {
            rc = die("z23-lint: read failed: %s\n", "Makefile");
            break;
        }
        /* bash `IFS=$'\t' read` collapses the delimiter tab with any
         * leading tabs on the argv line, so those tabs never appear. */
        const char *argv = line;
        while (*argv == '\t')
            argv++;
        rc = trs_on_recipe(out, cov, start, argv, &dep_total, &dep_seeded,
                           &cov_total, &fail);
        if (rc)
            break;
    }
    int fr = fin(f, line, "Makefile", rc);
    drop3(&seedre, &trig, &covre);
    regfree(&cont);
    if (fr)
        return fr;
    if (!found) {
        if (fputs("FAIL: found no compile-epoch-object.sh object recipes in Makefile\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (cov_total > 1) {
        if (fprintf(out,
                    "FAIL: expected exactly one coverage-mode object recipe, found %d.\n",
                    cov_total) < 0)
            return die("z23-lint: write failed\n", "");
        if (fputs("      The exemption is documented for one recipe; a second one has to\n"
                  "      justify itself rather than inherit the first one's reason.\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        fail = 1;
    }
    if (fail) {
        if (fputs("\n"
                  "Fix: append $(ZCL_TU_RANDOM_SEED) to the compiler argv of the object recipe.\n"
                  "     Proof of the property it buys: make repro-build\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return fprintf(out,
                   "check-tu-random-seed: PASS — %d/%d per-TU object recipes pin GCC's "
                   "random seed (%d coverage recipe exempt)\n",
                   dep_seeded, dep_total, cov_total) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int check_tu_random_seed_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return trs_check(stdout);
}

static const char k_trs_ok[] =
    "ZCL_TU_RANDOM_SEED = -frandom-seed=$<\n"
    "all:\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) dep \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(CFLAGS) $(ZCL_TU_RANDOM_SEED)\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) coverage \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(COV)\n";

static const char k_trs_missing[] =
    "all:\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) dep \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(CFLAGS) $(ZCL_TU_RANDOM_SEED)\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) coverage \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(COV)\n";

static const char k_trs_unseeded[] =
    "ZCL_TU_RANDOM_SEED = -frandom-seed=$<\n"
    "all:\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) dep \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(CFLAGS)\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) coverage \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(COV)\n";

static int check_tu_random_seed_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-trs-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile();
    if (!out) {
        rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char ob[4096];
    int bad = 0, rc = 0;
    if (chdir(root) != 0) {
        fclose(out);
        rmdir(root);
        return die("z23-lint: cannot scan %s\n", root);
    }

    if (csr_write("./Makefile", k_trs_missing))
        bad = 1;
    rc = trs_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: Makefile does not define ZCL_TU_RANDOM_SEED") == NULL;

    rewind(out);
    if (ftruncate(fileno(out), 0) != 0)
        bad = 1;
    if (csr_write("./Makefile", k_trs_ok))
        bad = 1;
    rc = trs_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check-tu-random-seed: PASS — 1/1 per-TU object recipes "
                      "pin GCC's random seed (1 coverage recipe exempt)") == NULL;

    rewind(out);
    if (ftruncate(fileno(out), 0) != 0)
        bad = 1;
    if (csr_write("./Makefile", k_trs_unseeded))
        bad = 1;
    rc = trs_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: Makefile:3 — per-TU object recipe does not carry $("
                      "ZCL_TU_RANDOM_SEED)") == NULL;

    fclose(out);
    unlink("./Makefile");
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_tu_random_seed selftest\n", stderr);
    return st_ok(bad, "check_tu_random_seed selftest: OK\n");
}

static const char *const k_rap_drop[] = {
    "__builtin_memcpy",
    "memcpy_uses_blob_var",
    "memcpys",
    "memcpy",
    "numcpus",
};

static int rap_ci_pref(const char *s, const char *n)
{
    for (; *n; s++, n++) {
        if (!*s)
            return 0;
        if (tolower((unsigned char)*s) != tolower((unsigned char)*n))
            return 0;
    }
    return 1;
}

static void rap_strip_one(char *s, const char *needle)
{
    char *w = s, *r = s;
    size_t nlen = strlen(needle);
    while (*r) {
        if (rap_ci_pref(r, needle))
            r += nlen;
        else
            *w++ = *r++;
    }
    *w = '\0';
}

static int rap_has_tok(const char *s, const char *tok)
{
    size_t n = strlen(tok);
    for (const char *p = s; *p; p++) {
        size_t i = 0;
        for (; i < n && p[i]; i++) {
            if (tolower((unsigned char)p[i]) != tolower((unsigned char)tok[i]))
                break;
        }
        if (i == n)
            return 1;
    }
    return 0;
}

struct rap_acc {
    const char *root;
    const char *tok;
    FILE *out;
    int tracked;
    int regular;
    int path_violation;
};

static int rap_on_track(const char *path, void *ctx)
{
    struct rap_acc *a = ctx;
    a->tracked++;
    char full[8192];
    if (ovf(snprintf(full, sizeof full, "%s/%s", a->root, path), sizeof full))
        return 2;
    struct stat st;
    if (stat(full, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    a->regular++;
    if (rap_has_tok(path, a->tok)) {
        if (fprintf(a->out, "FAIL: retired agent protocol in tracked path: %s\n",
                    path) < 0)
            return die("z23-lint: write failed\n", "");
        a->path_violation = 1;
    }
    return 0;
}

static int rap_filter(char *raw, const char *tok, FILE *out, int *hit)
{
    static char work[1024 * 1024];
    char *p = raw;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl)
            *nl = '\0';
        if (ovf(snprintf(work, sizeof work, "%s", p), sizeof work))
            return 2;
        for (size_t i = 0; i < sizeof k_rap_drop / sizeof k_rap_drop[0]; i++)
            rap_strip_one(work, k_rap_drop[i]);
        if (rap_has_tok(work, tok)) {
            if (fprintf(out, "%s\n", work) < 0)
                return die("z23-lint: write failed\n", "");
            *hit = 1;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

static int rap_git_cmd(const char *root, const char *rest, char *out, size_t cap,
                       int *code)
{
    char cmd[8192];
    if (strchr(root, '\''))
        return die("z23-lint: path too long: %s\n", root);
    if (ovf(snprintf(cmd, sizeof cmd, "git -C '%s' %s", root, rest), sizeof cmd))
        return 2;
    return capture_cmd(cmd, out, cap, code);
}

static int rap_scan(const char *root, FILE *out, FILE *err)
{
    char tok[4] = { 'm', 'c', 'p', 0 };
    char dump[64];
    int code = 0, rc;

    if (strchr(root, '\''))
        return die("z23-lint: path too long: %s\n", root);
    rc = rap_git_cmd(root, "rev-parse --is-inside-work-tree >/dev/null 2>&1",
                     dump, sizeof dump, &code);
    if (rc)
        return rc;
    if (code != 0) {
        if (fprintf(err,
                    "check_no_retired_agent_protocol: FATAL — '%s' is not a git worktree\n",
                    root) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }

    struct rap_acc a = { .root = root, .tok = tok, .out = out };
    char lscmd[8192];
    if (ovf(snprintf(lscmd, sizeof lscmd, "git -C '%s' ls-files -z", root),
            sizeof lscmd))
        return 2;
    rc = each_zpath(lscmd, rap_on_track, &a);
    if (rc)
        return rc;
    if (a.tracked == 0) {
        if (fputs("check_no_retired_agent_protocol: FATAL — tracked-file scan is empty\n",
                  err) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (a.regular == 0) {
        if (fputs("check_no_retired_agent_protocol: FATAL — no tracked regular files were scanned\n",
                  err) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }

    char greprest[64];
    if (ovf(snprintf(greprest, sizeof greprest, "grep -n -I -i -F '%s' -- .", tok),
            sizeof greprest))
        return 2;
    static char raw[4 * 1024 * 1024];
    rc = rap_git_cmd(root, greprest, raw, sizeof raw, &code);
    if (rc)
        return rc;
    if (code >= 2) {
        if (fprintf(err,
                    "check_no_retired_agent_protocol: FATAL — tracked-content scan failed (exit %d)\n",
                    code) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    int content_violation = 0;
    if (code == 0) {
        rc = rap_filter(raw, tok, out, &content_violation);
        if (rc)
            return rc;
    }
    if (a.path_violation || content_violation) {
        if (fputs("FAIL: retired agent protocol remains in tracked files.\n", out) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (fprintf(out,
                "  OK: %d tracked regular files contain no retired protocol token\n",
                a.regular) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int check_no_retired_agent_protocol_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (fputs("══ LINT: retired agent protocol absent from tracked files ══\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    char cwd[4096];
    const char *env = getenv("ZCL_RETIRED_PROTOCOL_ROOT");
    const char *root;
    if (env && env[0])
        root = env;
    else {
        if (!getcwd(cwd, sizeof cwd))
            return die("z23-lint: getcwd failed\n", "");
        root = cwd;
    }
    return rap_scan(root, stdout, stderr);
}

static int rap_rm_rf(const char *root)
{
    char cmd[8192], dump[64];
    int code = 0;
    if (strchr(root, '\''))
        return die("z23-lint: path too long: %s\n", root);
    if (ovf(snprintf(cmd, sizeof cmd, "rm -rf -- '%s'", root), sizeof cmd))
        return 2;
    return capture_cmd(cmd, dump, sizeof dump, &code);
}

static int check_no_retired_agent_protocol_selftest(void)
{
    char tok[4] = { 'm', 'c', 'p', 0 };
    char cap[4] = { 'M', 'c', 'p', 0 };
    char tmpl[] = "/tmp/z23-lint-rap-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile();
    if (!out) {
        (void)rap_rm_rf(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    const char *oldenv = getenv("ZCL_RETIRED_PROTOCOL_ROOT");
    char oldbuf[4096];
    int had_env = 0;
    if (oldenv) {
        if (ovf(snprintf(oldbuf, sizeof oldbuf, "%s", oldenv), sizeof oldbuf)) {
            fclose(out);
            (void)rap_rm_rf(root);
            return 2;
        }
        had_env = 1;
    }
    int bad = 0, rc = 0, code = 0;
    char dump[256], path[8192], body[128], addrest[256], nam[64];
    if (setenv("ZCL_RETIRED_PROTOCOL_ROOT", root, 1) != 0)
        bad = 1;
    rc = rap_git_cmd(root, "init -q", dump, sizeof dump, &code);
    if (rc || code != 0)
        bad = 1;

    if (ovf(snprintf(path, sizeof path, "%s/clean.c", root), sizeof path))
        bad = 1;
    else if (csr_write(path, "memcpy(buffer, source, length);\nnumcpus=4\n"))
        bad = 1;
    rc = rap_git_cmd(root, "add -- clean.c", dump, sizeof dump, &code);
    if (rc || code != 0)
        bad = 1;
    if (psp_st_reset(out))
        bad = 1;
    rc = rap_scan(root, out, stderr);
    if (rc != 0) {
        fputs("selftest: clean embedded substrings were rejected\n", stderr);
        bad = 1;
    }

    if (ovf(snprintf(path, sizeof path, "%s/untracked.txt", root), sizeof path)
        || ovf(snprintf(body, sizeof body, "Open%sClient\n", cap), sizeof body))
        bad = 1;
    else if (csr_write(path, body))
        bad = 1;
    if (psp_st_reset(out))
        bad = 1;
    rc = rap_scan(root, out, stderr);
    if (rc != 0) {
        fputs("selftest: untracked fixture entered the production scan\n", stderr);
        bad = 1;
    }

    rc = rap_git_cmd(root, "add -- untracked.txt", dump, sizeof dump, &code);
    if (rc || code != 0)
        bad = 1;
    if (psp_st_reset(out))
        bad = 1;
    rc = rap_scan(root, out, stderr);
    if (rc == 0) {
        fputs("selftest: tracked content violation was not detected\n", stderr);
        bad = 1;
    }
    rc = rap_git_cmd(root, "rm -q --cached untracked.txt", dump, sizeof dump, &code);
    if (rc || code != 0)
        bad = 1;
    if (ovf(snprintf(path, sizeof path, "%s/untracked.txt", root), sizeof path) == 0)
        unlink(path);

    if (ovf(snprintf(nam, sizeof nam, "old_%s_surface.txt", tok), sizeof nam)
        || ovf(snprintf(path, sizeof path, "%s/%s", root, nam), sizeof path)
        || ovf(snprintf(addrest, sizeof addrest, "add -- %s", nam), sizeof addrest))
        bad = 1;
    else if (csr_write(path, "clean body\n"))
        bad = 1;
    rc = rap_git_cmd(root, addrest, dump, sizeof dump, &code);
    if (rc || code != 0)
        bad = 1;
    if (psp_st_reset(out))
        bad = 1;
    rc = rap_scan(root, out, stderr);
    if (rc == 0) {
        fputs("selftest: tracked path violation was not detected\n", stderr);
        bad = 1;
    }

    fclose(out);
    if (had_env)
        (void)setenv("ZCL_RETIRED_PROTOCOL_ROOT", oldbuf, 1);
    else
        (void)unsetenv("ZCL_RETIRED_PROTOCOL_ROOT");
    (void)rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_no_retired_agent_protocol selftest\n", stderr);
    return st_ok(bad, "check_no_retired_agent_protocol selftest: OK\n");
}

static const char k_ssd_class[] = "tools/scripts/stopwatch_skip_class.sh";
static const char k_ssd_judge[] = "tools/scripts/stopwatch_evidence_judge.sh";
static const char k_ssd_def[] =
    "engine/services/include/services/stopwatch_skip_classes.def";
static const char k_ssd_table_cmd[] =
    "bash -c '. tools/scripts/stopwatch_skip_class.sh; stopwatch_skip_class_table' | grep -c '|'";

static int ssd_has_pass_line(const char *buf)
{
    static const char want[] = "selftest: PASS";
    size_t w = sizeof want - 1;
    const char *p = buf;
    for (;;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n == w && memcmp(p, want, w) == 0)
            return 1;
        if (!nl)
            return 0;
        p = nl + 1;
    }
}

static int ssd_run_selftest(FILE *out, const char *script, int *fail)
{
    if (!csr_readable(script)) {
        if (fprintf(out,
                    "FAIL: %s is missing — the skip-streak detector has no shell-side regression guard\n",
                    script) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
        return 0;
    }
    char cmd[512];
    static char captured[262144];
    if (ovf(snprintf(cmd, sizeof cmd, "bash %s --selftest 2>&1", script),
            sizeof cmd))
        return 2;
    int code = 0;
    int rc = capture_cmd(cmd, captured, sizeof captured, &code);
    if (rc)
        return rc;
    if (code != 0 || !ssd_has_pass_line(captured)) {
        if (fprintf(out, "FAIL: %s --selftest (rc=%d; no 'selftest: PASS' line)\n",
                    script, code) < 0)
            return die("z23-lint: write failed\n", "");
        if (fprintf(out, "%s\n", captured) < 0)
            return die("z23-lint: write failed\n", "");
        *fail = 1;
        return 0;
    }
    if (fprintf(out, "  ok: %s --selftest\n", script) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int ssd_count_def(int *count)
{
    regex_t re;
    int cr = compile_pat(&re, REG_EXTENDED,
                         "^STOPWATCH_SKIP_(CLASS|FALLBACK)\\(", "", "", "");
    if (cr)
        return cr;
    FILE *f = fopen(k_ssd_def, "r");
    if (!f) {
        *count = 0;
        regfree(&re);
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    *count = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (regexec(&re, line, 0, NULL, 0) == 0)
            (*count)++;
    }
    rc = fin(f, line, k_ssd_def, rc);
    regfree(&re);
    return rc;
}

static int ssd_check(FILE *out)
{
    (void)setenv("LC_ALL", "C", 1);
    int fail = 0, rc;
    rc = ssd_run_selftest(out, k_ssd_class, &fail);
    if (rc)
        return rc;
    rc = ssd_run_selftest(out, k_ssd_judge, &fail);
    if (rc)
        return rc;

    int rows_in_file = 0;
    rc = ssd_count_def(&rows_in_file);
    if (rc)
        return rc;
    char parsed[64];
    int code = 0;
    rc = capture_cmd(k_ssd_table_cmd, parsed, sizeof parsed, &code);
    if (rc)
        return rc;
    /* The original enables `set -e` inside run_selftest, so a failing
     * table pipeline (missing script, grep -c of zero matches) aborts
     * before the row-count comparison. */
    if (code != 0)
        return 1;
    int rows_parsed = atoi(parsed);
    if (rows_in_file < 5 || rows_in_file != rows_parsed) {
        if (fprintf(out, "FAIL: %s has %d rows but the shell parser sees %d\n",
                    k_ssd_def, rows_in_file, rows_parsed) < 0)
            return die("z23-lint: write failed\n", "");
        if (fputs("      Every row must be ENTIRELY on one line — the parser is line-oriented.\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        fail = 1;
    } else if (fprintf(out,
                       "  ok: %s — %d class rows, parsed identically by the shell side\n",
                       k_ssd_def, rows_in_file) < 0) {
        return die("z23-lint: write failed\n", "");
    }
    if (fail)
        return 1;
    return fputs("check_stopwatch_skip_detector: clean — shell skip-streak detector selftests pass\n",
                 out) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int check_stopwatch_skip_detector_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return ssd_check(stdout);
}

static const char k_ssd_class_ok[] =
    "stopwatch_skip_class_table() {\n"
    "echo 'a|'\n"
    "echo 'b|'\n"
    "echo 'c|'\n"
    "echo 'd|'\n"
    "echo 'e|'\n"
    "}\n"
    "if [ \"${1:-}\" = \"--selftest\" ]; then echo \"selftest: PASS\"; exit 0; fi\n";
static const char k_ssd_class_fail[] =
    "stopwatch_skip_class_table() {\n"
    "echo 'a|'\n"
    "}\n"
    "if [ \"${1:-}\" = \"--selftest\" ]; then echo \"selftest: FAIL\"; exit 1; fi\n";
static const char k_ssd_class_four[] =
    "stopwatch_skip_class_table() {\n"
    "echo 'a|'\n"
    "echo 'b|'\n"
    "echo 'c|'\n"
    "echo 'd|'\n"
    "}\n"
    "if [ \"${1:-}\" = \"--selftest\" ]; then echo \"selftest: PASS\"; exit 0; fi\n";
static const char k_ssd_judge_ok[] =
    "if [ \"${1:-}\" = \"--selftest\" ]; then echo \"selftest: PASS\"; exit 0; fi\n";
static const char k_ssd_def_five[] =
    "STOPWATCH_SKIP_CLASS(a, 1)\n"
    "STOPWATCH_SKIP_CLASS(b, 1)\n"
    "STOPWATCH_SKIP_CLASS(c, 1)\n"
    "STOPWATCH_SKIP_CLASS(d, 1)\n"
    "STOPWATCH_SKIP_FALLBACK(\"unclassified\", 2)\n";

static int check_stopwatch_skip_detector_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-ssd-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile();
    if (!out) {
        rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char ob[4096];
    int bad = 0, rc = 0;
    if (chdir(root) != 0) {
        fclose(out);
        rmdir(root);
        return die("z23-lint: cannot scan %s\n", root);
    }

    rc = ssd_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: tools/scripts/stopwatch_skip_class.sh is missing — "
                      "the skip-streak detector has no shell-side regression guard") == NULL;

    if (psp_st_reset(out))
        bad = 1;
    if (csr_write(k_ssd_class, k_ssd_class_fail)
        || csr_write(k_ssd_judge, k_ssd_judge_ok)
        || csr_write(k_ssd_def, k_ssd_def_five))
        bad = 1;
    rc = ssd_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: tools/scripts/stopwatch_skip_class.sh --selftest (rc=") == NULL
        || strstr(ob, "no 'selftest: PASS' line)") == NULL;

    if (psp_st_reset(out))
        bad = 1;
    if (csr_write(k_ssd_class, k_ssd_class_four))
        bad = 1;
    rc = ssd_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "FAIL: engine/services/include/services/stopwatch_skip_classes.def has 5 rows but the shell parser sees 4") == NULL;

    if (psp_st_reset(out))
        bad = 1;
    if (csr_write(k_ssd_class, k_ssd_class_ok))
        bad = 1;
    rc = ssd_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check_stopwatch_skip_detector: clean — shell skip-streak detector selftests pass") == NULL;

    fclose(out);
    unlink(k_ssd_class);
    unlink(k_ssd_judge);
    unlink(k_ssd_def);
    (void)rmdir("engine/services/include/services");
    (void)rmdir("engine/services/include");
    (void)rmdir("engine/services");
    (void)rmdir("engine");
    (void)rmdir("tools/scripts");
    (void)rmdir("tools");
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_stopwatch_skip_detector selftest\n", stderr);
    return st_ok(bad, "check_stopwatch_skip_detector selftest: OK\n");
}

static const char k_nws_self[] = "tools/lint/check_no_warning_suppression.sh";
static const char k_nws_ls[] =
    "ls-files -z -- Makefile makefile GNUmakefile '*.mk' '*.mak' '*.make' "
    "'*.c' '*.h' '*.sh'";

static int nws_comp(regex_t *flag, regex_t *pragma, regex_t *marker)
{
    char fp[96], pp[160], mp[64];
    if (ovf(snprintf(fp, sizeof fp, "-W" "no-(%s|%s)", "unused-result",
                     "stringop-overflow"), sizeof fp))
        return 2;
    if (ovf(snprintf(pp, sizeof pp,
                     "diagnostic[[:space:]]+ignored[[:space:]]+\"-W(%s|%s)",
                     "unused-result", "stringop-overflow"), sizeof pp))
        return 2;
    if (ovf(snprintf(mp, sizeof mp, "suppression-ok:[[:space:]]*[^[:space:]]"),
            sizeof mp))
        return 2;
    int e = regcomp(flag, fp, REG_EXTENDED);
    if (e)
        return reg_fail(flag, e);
    e = regcomp(pragma, pp, REG_EXTENDED);
    if (e) {
        regfree(flag);
        return reg_fail(pragma, e);
    }
    e = regcomp(marker, mp, REG_EXTENDED);
    if (e) {
        regfree(flag);
        regfree(pragma);
        return reg_fail(marker, e);
    }
    return 0;
}

static void nws_drop(regex_t *flag, regex_t *pragma, regex_t *marker)
{
    regfree(flag);
    regfree(pragma);
    regfree(marker);
}

struct nws_acc {
    const char *root;
    regex_t *flag, *pragma, *marker;
    FILE *hits;
    int scanned, nhits;
};

static int nws_on_track(const char *path, void *ctx)
{
    struct nws_acc *a = ctx;
    if (strncmp(path, "vendor/", 7) == 0 || strcmp(path, k_nws_self) == 0)
        return 0;
    char full[8192];
    if (ovf(snprintf(full, sizeof full, "%s/%s", a->root, path), sizeof full))
        return 2;
    struct stat st;
    if (stat(full, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    a->scanned++;
    FILE *f = fopen(full, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", full);
    static char prev[65536];
    prev[0] = '\0';
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (regexec(a->flag, line, 0, NULL, 0) == 0
            || regexec(a->pragma, line, 0, NULL, 0) == 0) {
            if (regexec(a->marker, line, 0, NULL, 0) != 0
                && regexec(a->marker, prev, 0, NULL, 0) != 0) {
                if (fprintf(a->hits, "%s:%d:%s\n", path, lineno, line) < 0) {
                    rc = die("z23-lint: write failed\n", "");
                    break;
                }
                a->nhits++;
            }
        }
        if (ovf(snprintf(prev, sizeof prev, "%s", line), sizeof prev)) {
            rc = 2;
            break;
        }
    }
    return fin(f, line, full, rc);
}

static int nws_scan(const char *root, FILE *out, FILE *err)
{
    regex_t flag, pragma, marker;
    int cr = nws_comp(&flag, &pragma, &marker);
    if (cr)
        return cr;
    FILE *hits = tmpfile();
    if (!hits) {
        nws_drop(&flag, &pragma, &marker);
        return die("z23-lint: tmpfile failed\n", "");
    }
    if (strchr(root, '\'')) {
        fclose(hits);
        nws_drop(&flag, &pragma, &marker);
        return die("z23-lint: path too long: %s\n", root);
    }
    char cmd[8192];
    if (ovf(snprintf(cmd, sizeof cmd, "git -C '%s' %s", root, k_nws_ls),
            sizeof cmd)) {
        fclose(hits);
        nws_drop(&flag, &pragma, &marker);
        return 2;
    }
    struct nws_acc a = {
        .root = root, .flag = &flag, .pragma = &pragma, .marker = &marker,
        .hits = hits
    };
    int rc = each_zpath(cmd, nws_on_track, &a);
    if (rc) {
        fclose(hits);
        nws_drop(&flag, &pragma, &marker);
        return rc;
    }
    if (a.scanned < 1) {
        fclose(hits);
        nws_drop(&flag, &pragma, &marker);
        if (fputs("check_no_warning_suppression: FATAL — build-surface scan set is empty\n",
                  err) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (a.nhits) {
        if (fseek(hits, 0, SEEK_SET) != 0) {
            fclose(hits);
            nws_drop(&flag, &pragma, &marker);
            return die("z23-lint: fseek failed\n", "");
        }
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        while ((n = getline(&line, &cap, hits)) >= 0) {
            if (n > 0 && line[n - 1] == '\n')
                line[n - 1] = '\0';
            if (fprintf(err, "FAIL: unmarked warning suppression — %s\n", line) < 0) {
                free(line);
                fclose(hits);
                nws_drop(&flag, &pragma, &marker);
                return die("z23-lint: write failed\n", "");
            }
        }
        free(line);
        fclose(hits);
        nws_drop(&flag, &pragma, &marker);
        if (fprintf(err,
                    "check_no_warning_suppression: FAIL — hits=%d scanned=%d\n",
                    a.nhits, a.scanned) < 0)
            return die("z23-lint: write failed\n", "");
        if (fprintf(err,
                    "  -W" "no-%s also disables [[nodiscard]] reporting; -W"
                    "no-%s hides\n",
                    "unused-result", "stringop-overflow") < 0)
            return die("z23-lint: write failed\n", "");
        if (fputs("  a memory-safety diagnostic. Delete the flag, or state the reason on the line above it:\n",
                  err) < 0)
            return die("z23-lint: write failed\n", "");
        if (fputs("      # suppression-ok: <why this build surface genuinely needs it>\n",
                  err) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    fclose(hits);
    nws_drop(&flag, &pragma, &marker);
    if (fprintf(out, "check_no_warning_suppression: clean — scanned=%d build surfaces\n",
                a.scanned) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int nws_fx_fail(const char *why)
{
    if (fprintf(stderr,
                "z23-lint: INTERNAL — check_no_warning_suppression fixture: %s\n",
                why) < 0)
        return die("z23-lint: write failed\n", "");
    return 3;
}

static int nws_fx_write(const char *path, const char *kind, const char *extra)
{
    char body[512];
    if (kind) {
        if (ovf(snprintf(body, sizeof body, "CFLAGS += -W" "no-%s%s", kind,
                         extra ? extra : "\n"), sizeof body))
            return 2;
        return csr_write(path, body);
    }
    return csr_write(path, extra);
}

static int nws_fixtures(void)
{
    char tmpl[] = "/tmp/z23-lint-nws-XXXXXX";
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *cap = tmpfile();
    if (!cap) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char repo[4096], empty[4096], path[8192], body[512], ob[4096], dump[64];
    int code = 0, rc = 0, scan_rc = 0, bad = 0;
    if (ovf(snprintf(repo, sizeof repo, "%s/repo", tmp), sizeof repo)
        || ovf(snprintf(empty, sizeof empty, "%s/empty", tmp), sizeof empty))
        bad = 1;
    if (!bad
        && (csr_mkdirs(repo) || csr_mkdirs(empty)
            || ovf(snprintf(path, sizeof path, "%s/tools/lint", repo), sizeof path)
            || csr_mkdirs(path)
            || ovf(snprintf(path, sizeof path, "%s/vendor", repo), sizeof path)
            || csr_mkdirs(path)))
        bad = 1;
    if (!bad && (rap_git_cmd(repo, "init -q", dump, sizeof dump, &code) || code))
        bad = 1;
    if (!bad && (rap_git_cmd(empty, "init -q", dump, sizeof dump, &code) || code))
        bad = 1;
    if (!bad) {
        if (ovf(snprintf(path, sizeof path, "%s/Makefile", repo), sizeof path)
            || csr_write(path, "CFLAGS = -std=c23 -Wall -Wextra -Werror\n")
            || ovf(snprintf(path, sizeof path, "%s/a.c", repo), sizeof path)
            || csr_write(path, "int main(void){return 0;}\n")
            || ovf(snprintf(path, sizeof path, "%s/vendor/third_party.mk", repo),
                   sizeof path)
            || nws_fx_write(path, "unused-result", "\n"))
            bad = 1;
    }
    if (!bad
        && (rap_git_cmd(repo, "add Makefile a.c vendor/third_party.mk", dump,
                        sizeof dump, &code)
            || code))
        bad = 1;
    if (bad) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant detector fixture");
    }

    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 0 || strstr(ob, "check_no_warning_suppression: clean") == NULL) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("clean fixture rejected");
    }
    if (strstr(ob, "vendor/third_party.mk") != NULL) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("vendor/ must be out of scope");
    }

    if (ovf(snprintf(path, sizeof path, "%s/Makefile", repo), sizeof path)
        || ovf(snprintf(body, sizeof body,
                        "CFLAGS = -std=c23 -Wall -Wextra -Werror\n"
                        "CFLAGS += -W" "no-%s\n",
                        "unused-result"), sizeof body)
        || csr_write(path, body)) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant flag-form fixture");
    }
    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 1 || strstr(ob, "Makefile:2") == NULL) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("flag form did not trip Makefile:2");
    }

    if (ovf(snprintf(body, sizeof body,
                     "# suppression-ok:\nCFLAGS += -W" "no-%s\n",
                     "unused-result"), sizeof body)
        || csr_write(path, body)) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant empty-reason fixture");
    }
    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 1) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("empty-reason marker must not exempt");
    }

    if (ovf(snprintf(body, sizeof body,
                     "# suppression-ok: fixture proves the marker is honoured\n"
                     "CFLAGS += -W" "no-%s\n",
                     "unused-result"), sizeof body)
        || csr_write(path, body)) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant preceding-line fixture");
    }
    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 0) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("preceding-line marker not honoured");
    }

    if (ovf(snprintf(body, sizeof body,
                     "CFLAGS += -W" "no-%s  # suppression-ok: fixture\n",
                     "stringop-overflow"), sizeof body)
        || csr_write(path, body)) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant same-line fixture");
    }
    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 0) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("same-line marker not honoured");
    }

    if (csr_write(path, "CFLAGS = -Wall\n")
        || ovf(snprintf(path, sizeof path, "%s/a.c", repo), sizeof path)
        || ovf(snprintf(body, sizeof body,
                        "#pragma GCC diagnostic ignored \"-W%s\"\n"
                        "int main(void){return 0;}\n",
                        "unused-result"), sizeof body)
        || csr_write(path, body)) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("could not plant pragma fixture");
    }
    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(repo, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 1 || strstr(ob, "a.c:1") == NULL) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("pragma form did not trip a.c:1");
    }

    if (psp_st_reset(cap))
        bad = 1;
    scan_rc = nws_scan(empty, cap, cap);
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    if (bad || scan_rc != 2 || strstr(ob, "FATAL") == NULL) {
        fclose(cap);
        (void)rap_rm_rf(tmp);
        return nws_fx_fail("empty scan expected FATAL exit 2");
    }

    fclose(cap);
    rc = rap_rm_rf(tmp);
    return rc ? rc : 0;
}

static int check_no_warning_suppression_run(int argc, char **argv)
{
    char cwd[4096];
    const char *root;
    if (argc >= 1 && argv[0] && argv[0][0])
        root = argv[0];
    else {
        if (!getcwd(cwd, sizeof cwd))
            return die("z23-lint: getcwd failed\n", "");
        root = cwd;
    }
    struct stat st;
    if (stat(root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (fprintf(stderr,
                    "check_no_warning_suppression: FATAL — root is not a directory: %s\n",
                    root) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (strchr(root, '\''))
        return die("z23-lint: path too long: %s\n", root);
    char dump[64];
    int code = 0;
    int rc = rap_git_cmd(root, "rev-parse --is-inside-work-tree >/dev/null 2>&1",
                         dump, sizeof dump, &code);
    if (rc)
        return rc;
    if (code != 0) {
        if (fprintf(stderr,
                    "check_no_warning_suppression: FATAL — not a Git worktree: %s\n",
                    root) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    rc = nws_fixtures();
    if (rc)
        return rc;
    return nws_scan(root, stdout, stderr);
}

static int check_no_warning_suppression_selftest(void)
{
    int rc = nws_fixtures();
    if (rc) {
        fputs("FAIL: check_no_warning_suppression selftest\n", stderr);
        return st_ok(1, "check_no_warning_suppression selftest: OK\n");
    }
    return st_ok(0, "check_no_warning_suppression selftest: OK\n");
}

enum {
    PTR_LEAF_MAX = 1024,
    PTR_LEAF_LEN = 192,
    PTR_DISP_LEN = 1024,
    PTR_FILE_MAX = 2 * 1024 * 1024
};

static char g_ptr_file[PTR_FILE_MAX];
static char g_ptr_leaf[PTR_LEAF_MAX][PTR_LEAF_LEN];
static char g_ptr_dkey[PTR_LEAF_MAX][PTR_LEAF_LEN];
static char g_ptr_dval[PTR_LEAF_MAX][PTR_DISP_LEN];

static int ptr_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int ptr_add_leaf(const char *path, int *nleaf)
{
    if (!path[0])
        return 0;
    if (*nleaf >= PTR_LEAF_MAX)
        return die("z23-lint: derived buffer overflow\n", "");
    return ovf(snprintf(g_ptr_leaf[*nleaf], PTR_LEAF_LEN, "%s", path),
               PTR_LEAF_LEN) ? 2 : ((*nleaf)++, 0);
}

static int ptr_tok_at(const char *buf, size_t n, size_t i, size_t *len)
{
    static const char *const toks[] = {
        "ZCL_COMMAND_READY_COMMAND(",
        "ZCL_COMMAND_PLANNED_COMMAND(",
        "ZCL_COMMAND_COMPAT_COMMAND(",
        "ZCL_COMMAND_DEV_COMMAND(",
    };
    for (size_t t = 0; t < sizeof toks / sizeof toks[0]; t++) {
        size_t L = strlen(toks[t]);
        if (i + L <= n && memcmp(buf + i, toks[t], L) == 0) {
            *len = L;
            return 1;
        }
    }
    return 0;
}

static int ptr_parse_buf(char *buf, size_t n, int *nleaf)
{
    size_t i = 0;
    while (i < n) {
        size_t L = 0;
        if (!ptr_tok_at(buf, n, i, &L)) {
            i++;
            continue;
        }
        size_t j = i + L;
        int depth = 1, in_str = 0, esc = 0;
        size_t spec_at = j;
        while (j < n && depth > 0) {
            char c = buf[j];
            if (in_str) {
                if (esc)
                    esc = 0;
                else if (c == '\\')
                    esc = 1;
                else if (c == '"')
                    in_str = 0;
            } else if (c == '"')
                in_str = 1;
            else if (c == '(')
                depth++;
            else if (c == ')')
                depth--;
            j++;
        }
        size_t spec_end = (depth == 0) ? j - 1 : j;
        char save = buf[spec_end];
        buf[spec_end] = '\0';
        const char *spec = buf + spec_at;
        char path[PTR_LEAF_LEN];
        path[0] = '\0';
        const char *q1 = strchr(spec, '"');
        if (q1) {
            const char *q2 = strchr(q1 + 1, '"');
            if (q2) {
                size_t pl = (size_t)(q2 - q1 - 1);
                if (pl >= sizeof path) {
                    buf[spec_end] = save;
                    return die("z23-lint: derived buffer overflow\n", "");
                }
                memcpy(path, q1 + 1, pl);
                path[pl] = '\0';
            }
        }
        int owner = strstr(spec, "ZCL_COMMAND_AUTH_OWNER") != NULL;
        int mutate = strstr(spec, "ZCL_COMMAND_EFFECT_MUTATE") != NULL
                  || strstr(spec, "ZCL_COMMAND_EFFECT_DESTRUCTIVE") != NULL;
        int rcadd = 0;
        if (owner && mutate && path[0])
            rcadd = ptr_add_leaf(path, nleaf);
        buf[spec_end] = save;
        if (rcadd)
            return rcadd;
        i = j;
    }
    return 0;
}

static int ptr_read_file(const char *path, char *buf, size_t cap, size_t *outn)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    size_t n = fread(buf, 1, cap - 1, f);
    if (n == cap - 1) {
        char extra;
        if (fread(&extra, 1, 1, f) == 1) {
            fclose(f);
            return die("z23-lint: derived buffer overflow\n", "");
        }
    }
    int err = ferror(f);
    if (fclose(f) != 0 && !err)
        return die("z23-lint: fclose failed: %s\n", path);
    if (err)
        return die("z23-lint: read failed: %s\n", path);
    buf[n] = '\0';
    *outn = n;
    return 0;
}

static const char *ptr_disp_get(int ndisp, const char *leaf)
{
    for (int i = 0; i < ndisp; i++) {
        if (strcmp(g_ptr_dkey[i], leaf) == 0)
            return g_ptr_dval[i];
    }
    return NULL;
}

static int ptr_disp_set(int *ndisp, const char *leaf, const char *rest)
{
    for (int i = 0; i < *ndisp; i++) {
        if (strcmp(g_ptr_dkey[i], leaf) == 0)
            return ovf(snprintf(g_ptr_dval[i], PTR_DISP_LEN, "%s", rest),
                       PTR_DISP_LEN);
    }
    if (*ndisp >= PTR_LEAF_MAX)
        return die("z23-lint: derived buffer overflow\n", "");
    if (ovf(snprintf(g_ptr_dkey[*ndisp], PTR_LEAF_LEN, "%s", leaf), PTR_LEAF_LEN))
        return 2;
    if (ovf(snprintf(g_ptr_dval[*ndisp], PTR_DISP_LEN, "%s", rest), PTR_DISP_LEN))
        return 2;
    (*ndisp)++;
    return 0;
}

static int ptr_replay_pref(FILE *src, FILE *err)
{
    if (fseek(src, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, src)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (fprintf(err, "  %s\n", line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    free(line);
    return rc;
}

static int ptr_scan(const char *defdir, const char *baseline, const char *workdir,
                    FILE *out, FILE *err)
{
    int def_count = 0, nleaf = 0, ndisp = 0;
    struct stat dst;
    if (stat(defdir, &dst) == 0 && S_ISDIR(dst.st_mode)) {
        DIR *d = opendir(defdir);
        if (!d)
            return die("z23-lint: cannot open %s\n", defdir);
        struct dirent *de;
        int prc = 0;
        while (prc == 0 && (de = readdir(d)) != NULL) {
            const char *nm = de->d_name;
            size_t L = strlen(nm);
            if (L < 5 || nm[0] == '.' || strcmp(nm + L - 4, ".def") != 0)
                continue;
            char full[8192];
            if (ovf(snprintf(full, sizeof full, "%s/%s", defdir, nm), sizeof full)) {
                prc = 2;
                break;
            }
            struct stat st;
            if (stat(full, &st) != 0 || !S_ISREG(st.st_mode))
                continue;
            def_count++;
            size_t got = 0;
            prc = ptr_read_file(full, g_ptr_file, sizeof g_ptr_file, &got);
            if (prc == 0)
                prc = ptr_parse_buf(g_ptr_file, got, &nleaf);
        }
        closedir(d);
        if (prc)
            return prc;
    }

    if (nleaf > 1)
        qsort(g_ptr_leaf, (size_t)nleaf, PTR_LEAF_LEN, ptr_cmp);
    int w = 0;
    for (int i = 0; i < nleaf; i++) {
        if (w && strcmp(g_ptr_leaf[w - 1], g_ptr_leaf[i]) == 0)
            continue;
        if (w != i)
            memcpy(g_ptr_leaf[w], g_ptr_leaf[i], PTR_LEAF_LEN);
        w++;
    }
    nleaf = w;

    if (def_count == 0 || nleaf == 0) {
        if (fprintf(err,
                    "check_privileged_transition_receipt: FATAL — no owner-mutating leaves enumerated from %s/*.def (broken scan; refusing a hollow clean).\n",
                    defdir) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }

    FILE *bf = fopen(baseline, "r");
    if (bf) {
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        int brc = 0;
        while (brc == 0 && (n = getline(&line, &cap, bf)) >= 0) {
            if (n > 0 && line[n - 1] == '\n')
                line[n - 1] = '\0';
            char *p = line;
            while (*p && isspace((unsigned char)*p))
                p++;
            if (!*p || *p == '#')
                continue;
            char *leaf = p;
            while (*p && !isspace((unsigned char)*p))
                p++;
            char *rest = p;
            if (*p) {
                *p++ = '\0';
                while (*p && isspace((unsigned char)*p))
                    p++;
                rest = p;
            }
            brc = ptr_disp_set(&ndisp, leaf, rest);
        }
        int fr = fin(bf, line, baseline, brc);
        if (fr)
            return fr;
    }

    regex_t vre;
    int e = regcomp(&vre,
                    "authority_receipt_[a-z_]*_available[(]|"
                    "consensus_state_replay_receipt_authority_available[(]",
                    REG_EXTENDED);
    if (e)
        return reg_fail(&vre, e);

    FILE *violf = tmpfile(), *lostf = tmpfile();
    if (!violf || !lostf) {
        if (violf) fclose(violf);
        if (lostf) fclose(lostf);
        regfree(&vre);
        return die("z23-lint: tmpfile failed\n", "");
    }

    int n_total = 0, n_receipt = 0, n_exempt = 0, nviol = 0, nlost = 0, fail = 0;
    int rc = 0;
    for (int i = 0; i < nleaf && rc == 0; i++) {
        n_total++;
        const char *d = ptr_disp_get(ndisp, g_ptr_leaf[i]);
        if (!d || !d[0]) {
            if (fprintf(violf, "%s\n", g_ptr_leaf[i]) < 0)
                rc = die("z23-lint: write failed\n", "");
            nviol++;
            continue;
        }
        if (strncmp(d, "receipt:", 8) == 0)
            n_receipt++;
        else if (strncmp(d, "exempt:", 7) == 0)
            n_exempt++;
        else if (fprintf(violf,
                         "%s (malformed disposition: '%s' — must start receipt: or exempt:)\n",
                         g_ptr_leaf[i], d) < 0)
            rc = die("z23-lint: write failed\n", "");
        else
            nviol++;
    }

    for (int i = 0; i < ndisp && rc == 0; i++) {
        const char *d = g_ptr_dval[i];
        if (strncmp(d, "receipt:", 8) != 0)
            continue;
        const char *spec = d + 8;
        size_t fl = 0;
        while (spec[fl] && !isspace((unsigned char)spec[fl]))
            fl++;
        if (fl == 0 || fl >= 4096) {
            rc = die("z23-lint: derived buffer overflow\n", "");
            break;
        }
        char file[4096];
        memcpy(file, spec, fl);
        file[fl] = '\0';
        char full[8192];
        const char *openp = file;
        if (file[0] != '/') {
            if (ovf(snprintf(full, sizeof full, "%s/%s", workdir, file),
                    sizeof full)) {
                rc = 2;
                break;
            }
            openp = full;
        }
        struct stat st;
        if (stat(openp, &st) != 0 || !S_ISREG(st.st_mode)) {
            if (fprintf(lostf, "%s -> %s (file not found)\n", g_ptr_dkey[i], file) < 0)
                rc = die("z23-lint: write failed\n", "");
            nlost++;
            continue;
        }
        size_t got = 0;
        rc = ptr_read_file(openp, g_ptr_file, sizeof g_ptr_file, &got);
        if (rc)
            break;
        if (regexec(&vre, g_ptr_file, 0, NULL, 0) != 0) {
            if (fprintf(lostf, "%s -> %s (no authority_receipt verify call)\n",
                        g_ptr_dkey[i], file) < 0)
                rc = die("z23-lint: write failed\n", "");
            nlost++;
        }
    }
    regfree(&vre);
    if (rc) {
        fclose(violf);
        fclose(lostf);
        return rc;
    }

    if (nviol) {
        fail = 1;
        if (fprintf(err,
                    "check_privileged_transition_receipt: owner-mutating leaf/leaves with NO Law-7 disposition in %s:\n",
                    baseline) < 0) {
            fclose(violf);
            fclose(lostf);
            return die("z23-lint: write failed\n", "");
        }
        rc = ptr_replay_pref(violf, err);
        if (rc == 0
            && (fputs("\n", err) < 0
                || fputs("Every ZCL_COMMAND_AUTH_OWNER + EFFECT_MUTATE/DESTRUCTIVE leaf must be dispositioned. Add ONE line:\n",
                         err) < 0
                || fputs("  <leaf.path>  receipt:<relative_handler_file>   # if it installs a privileged artifact — bind authority_receipt_header_* (or the replay-receipt verifier) over {artifact digest, context anchor, running binary}\n",
                         err) < 0
                || fputs("  <leaf.path>  exempt:<one-line reason>          # if it is not an artifact-install transition\n",
                         err) < 0))
            rc = die("z23-lint: write failed\n", "");
    }
    if (rc == 0 && nlost) {
        fail = 1;
        if (fputs("check_privileged_transition_receipt: a receipt: consumer no longer gates on an authority receipt:\n",
                  err) < 0)
            rc = die("z23-lint: write failed\n", "");
        else
            rc = ptr_replay_pref(lostf, err);
        if (rc == 0
            && fputs("  A wired privileged transition must keep calling authority_receipt_*_available( before mutating.\n",
                     err) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    fclose(violf);
    fclose(lostf);
    if (rc)
        return rc;
    if (fail)
        return 1;
    if (fprintf(out,
                "check_privileged_transition_receipt: clean — %d owner-mutating leaves, all dispositioned (%d receipt, %d exempt)\n",
                n_total, n_receipt, n_exempt) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int check_privileged_transition_receipt_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char cwd[4096], basebuf[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    const char *envd = getenv("ZCL_PRIV_RECEIPT_DEF_DIR");
    const char *envb = getenv("ZCL_PRIV_RECEIPT_BASELINE");
    const char *defdir = (envd && envd[0]) ? envd : "engine/composition/commands";
    const char *baseline;
    if (envb && envb[0])
        baseline = envb;
    else {
        if (ovf(snprintf(basebuf, sizeof basebuf,
                         "%s/tools/lint/privileged_transition_receipt_baseline.txt",
                         cwd), sizeof basebuf))
            return 2;
        baseline = basebuf;
    }
    return ptr_scan(defdir, baseline, cwd, stdout, stderr);
}

static int ptr_st_env(const char *defdir, const char *baseline)
{
    if (setenv("ZCL_PRIV_RECEIPT_DEF_DIR", defdir, 1) != 0
        || setenv("ZCL_PRIV_RECEIPT_BASELINE", baseline, 1) != 0)
        return 1;
    return 0;
}

static int ptr_st_clear_env(int had_d, const char *oldd, int had_b, const char *oldb)
{
    if (had_d)
        (void)setenv("ZCL_PRIV_RECEIPT_DEF_DIR", oldd, 1);
    else
        (void)unsetenv("ZCL_PRIV_RECEIPT_DEF_DIR");
    if (had_b)
        (void)setenv("ZCL_PRIV_RECEIPT_BASELINE", oldb, 1);
    else
        (void)unsetenv("ZCL_PRIV_RECEIPT_BASELINE");
    return 0;
}

static int check_privileged_transition_receipt_selftest(void)
{
    char tmpl[] = "/tmp/z23-lint-ptr-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        (void)rap_rm_rf(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    const char *ed = getenv("ZCL_PRIV_RECEIPT_DEF_DIR");
    const char *eb = getenv("ZCL_PRIV_RECEIPT_BASELINE");
    char oldd[4096], oldb[4096];
    int had_d = 0, had_b = 0, bad = 0, rc = 0;
    if (ed) {
        if (ovf(snprintf(oldd, sizeof oldd, "%s", ed), sizeof oldd))
            bad = 1;
        else
            had_d = 1;
    }
    if (eb) {
        if (ovf(snprintf(oldb, sizeof oldb, "%s", eb), sizeof oldb))
            bad = 1;
        else
            had_b = 1;
    }

    char defs[4096], empty[4096], base[4096], handler[4096], defa[4096], ob[8192],
        ebout[8192];
    static const char k_def[] =
        "ZCL_COMMAND_READY_COMMAND(\n"
        "    \"app.test.clean\", \"parent\", \"has (parens) and \\\"quotes\\\" inside\",\n"
        "    ZCL_COMMAND_AUTH_OWNER, ZCL_COMMAND_EFFECT_MUTATE)\n"
        "ZCL_COMMAND_DEV_COMMAND(\n"
        "    \"app.test.dev\", ZCL_COMMAND_AUTH_OWNER, ZCL_COMMAND_EFFECT_DESTRUCTIVE)\n";
    static const char k_pub[] =
        "ZCL_COMMAND_READY_COMMAND(\n"
        "    \"app.test.public\", ZCL_COMMAND_AUTH_PUBLIC, ZCL_COMMAND_EFFECT_MUTATE)\n";
    if (ovf(snprintf(defs, sizeof defs, "%s/defs", root), sizeof defs)
        || ovf(snprintf(empty, sizeof empty, "%s/empty", root), sizeof empty)
        || ovf(snprintf(base, sizeof base, "%s/baseline.txt", root), sizeof base)
        || ovf(snprintf(handler, sizeof handler, "%s/handler.c", root), sizeof handler)
        || ovf(snprintf(defa, sizeof defa, "%s/defs/a.def", root), sizeof defa)
        || csr_mkdirs(defs) || csr_mkdirs(empty) || csr_write(defa, k_def))
        bad = 1;

    if (!bad && ptr_st_env(defs, base))
        bad = 1;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(base,
                  "app.test.clean  exempt: fixture\n"
                  "app.test.dev    exempt: fixture\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check_privileged_transition_receipt: clean — 2 owner-mutating leaves, all dispositioned (0 receipt, 2 exempt)") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(base, "# none\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 1
        || strstr(ebout, "app.test.clean") == NULL
        || strstr(ebout, "app.test.dev") == NULL
        || strstr(ebout, "Every ZCL_COMMAND_AUTH_OWNER + EFFECT_MUTATE/DESTRUCTIVE leaf must be dispositioned.") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(base,
                  "app.test.clean  nope:xyz\n"
                  "app.test.dev    exempt: fixture\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 1
        || strstr(ebout, "app.test.clean (malformed disposition: 'nope:xyz' — must start receipt: or exempt:)") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(handler, "int x(void) { authority_receipt_x_available(0); return 0; }\n")
        || csr_write(base,
                     "app.test.clean  receipt:handler.c\n"
                     "app.test.dev    exempt: fixture\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "(1 receipt, 1 exempt)") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(handler, "int x(void) { return 0; }\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 1
        || strstr(ebout, "app.test.clean -> handler.c (no authority_receipt verify call)") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(base,
                  "app.test.clean  receipt:missing.c\n"
                  "app.test.dev    exempt: fixture\n"))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 1
        || strstr(ebout, "app.test.clean -> missing.c (file not found)") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    rc = ptr_scan(empty, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 2 || strstr(ebout, "FATAL") == NULL;

    if (psp_st_reset(out) || psp_st_reset(err))
        bad = 1;
    if (csr_write(defa, k_pub))
        bad = 1;
    rc = ptr_scan(defs, base, root, out, err);
    if (csr_slurp(out, ob, sizeof ob) || csr_slurp(err, ebout, sizeof ebout))
        bad = 1;
    bad |= rc != 2 || strstr(ebout, "FATAL") == NULL;

    fclose(out);
    fclose(err);
    ptr_st_clear_env(had_d, oldd, had_b, oldb);
    (void)rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_privileged_transition_receipt selftest\n", stderr);
    return st_ok(bad, "check_privileged_transition_receipt selftest: OK\n");
}

enum { CBF_MAX = 256, CBF_PATH = 256 };
static const char k_cbf_def[] = "engine/jobs/src/stage_repair_coin_backfill.c";
static const char k_cbf_allow[] =
    "engine/reducer/jobs/src/stage_repair_reducer_frontier_coin.c";
static const char *const k_cbf_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};
struct cbf_ent { char path[CBF_PATH]; int count; };
struct cbf_acc { const char *sym; struct cbf_ent *ent; int n; };

static void cbf_sym(char *buf, size_t cap)
{
    (void)snprintf(buf, cap, "%s%s", "stage_repair_coin_backfill_try", "(");
}

static int cbf_cmp(const void *a, const void *b)
{
    return strcmp(((const struct cbf_ent *)a)->path,
                  ((const struct cbf_ent *)b)->path);
}

static int cbf_count(const char *path, const char *sym, int *count)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0, slen = strlen(sym);
    *count = 0;
    while (getline(&line, &cap, f) >= 0) {
        for (char *p = line; slen && (p = strstr(p, sym)) != NULL; p += slen)
            (*count)++;
    }
    return fin(f, line, path, 0);
}

static int cbf_on_file(const char *path, void *ctx)
{
    struct cbf_acc *a = ctx;
    if (strcmp(path, k_cbf_def) == 0 || lint_path_is_excluded(path))
        return 0;
    int n = 0, rc = cbf_count(path, a->sym, &n);
    if (rc)
        return rc;
    if (n <= 0)
        return 0;
    size_t pl = strlen(path);
    if (a->n >= CBF_MAX || pl >= CBF_PATH)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(a->ent[a->n].path, path, pl + 1);
    a->ent[a->n].count = n;
    a->n++;
    return 0;
}

static int cbf_has_sym(const char *path, const char *sym)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0)
        found = strstr(line, sym) != NULL;
    (void)fin(f, line, path, 0);
    return found;
}

static int cbf_scan(FILE *out)
{
    char sym[64];
    cbf_sym(sym, sizeof sym);
    if (!cbf_has_sym(k_cbf_def, sym)) {
        if (fprintf(out, "check_no_new_coin_backfill_caller: FATAL — '%s' no longer found in %s.\n",
                    sym, k_cbf_def) < 0
            || fputs("  - If the coin-backfill ladder was deleted, remove this gate and its Makefile wiring.\n",
                     out) < 0
            || fputs("  - If it moved or was renamed, update DEF_FILE/SYMBOL so the ratchet keeps firing.\n",
                     out) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    struct cbf_ent ent[CBF_MAX];
    struct cbf_acc a = { .sym = sym, .ent = ent, .n = 0 };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_cbf_roots / sizeof k_cbf_roots[0]; i++)
        rc = walk_src(k_cbf_roots[i], 0, cbf_on_file, &a);
    if (rc)
        return rc;
    qsort(ent, (size_t)a.n, sizeof ent[0], cbf_cmp);
    int allowed_count = 0, nbad = 0, bad_i[CBF_MAX];
    for (int i = 0; i < a.n; i++) {
        if (strcmp(ent[i].path, k_cbf_allow) == 0)
            allowed_count += ent[i].count;
        else
            bad_i[nbad++] = i;
    }
    if (nbad == 0 && allowed_count == 1)
        return fputs("check_no_new_coin_backfill_caller: clean — one allowed production caller\n",
                     out) < 0 ? die("z23-lint: write failed\n", "") : 0;
    if (fputc('\n', out) == EOF)
        return die("z23-lint: write failed\n", "");
    if (allowed_count != 1
        && fprintf(out, "check_no_new_coin_backfill_caller: expected exactly 1 call in %s, found %d\n",
                   k_cbf_allow, allowed_count) < 0)
        return die("z23-lint: write failed\n", "");
    if (nbad) {
        if (fprintf(out, "check_no_new_coin_backfill_caller: NEW production caller(s) of %s:\n",
                    sym) < 0)
            return die("z23-lint: write failed\n", "");
        for (int i = 0; i < nbad; i++) {
            int j = bad_i[i];
            if (fprintf(out, "  %s:%d\n", ent[j].path, ent[j].count) < 0)
                return die("z23-lint: write failed\n", "");
        }
    }
    if (fputc('\n', out) == EOF
        || fputs("Do NOT add another coin-backfill repair entry caller. Route reducer-frontier\n",
                 out) < 0
        || fputs("repair evidence through the existing dispatcher, or delete/shrink this ladder\n",
                 out) < 0
        || fputs("after the self-verified UTXO anchor rebuild cure (-refold-from-anchor).\n",
                 out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int cbf_with_root(const char *root, FILE *out)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    int rc = cbf_scan(out);
    if (chdir(cwd) != 0 && rc == 0)
        rc = die("z23-lint: getcwd failed\n", "");
    return rc;
}

static const char *cbf_root(int argc, char **argv)
{
    const char *env = getenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST");
    if (env && env[0])
        return env;
    if (argc >= 1 && argv[0] && argv[0][0])
        return argv[0];
    return ".";
}

static int check_no_new_coin_backfill_caller_run(int argc, char **argv)
{
    return cbf_with_root(cbf_root(argc, argv), stdout);
}

static int cbf_st_run(FILE *cap, int *rc)
{
    if (psp_st_reset(cap))
        return 1;
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    if (saved < 0)
        return 1;
    if (dup2(fileno(cap), STDOUT_FILENO) < 0) {
        close(saved);
        return 1;
    }
    *rc = check_no_new_coin_backfill_caller_run(0, NULL);
    fflush(stdout);
    (void)dup2(saved, STDOUT_FILENO);
    close(saved);
    return 0;
}

static int check_no_new_coin_backfill_caller_selftest(void)
{
    char tmpl[] = "/tmp/z23-lint-cbf-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *cap = tmpfile();
    if (!cap) {
        (void)rap_rm_rf(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    const char *old_root = getenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST");
    const char *old_prod = getenv("ZCL_LINT_PRODUCTION_SCAN");
    char oldr[4096], oldp[64];
    int had_root = 0, had_prod = 0, bad = 0, rc = 0;
    if (old_root) {
        if (ovf(snprintf(oldr, sizeof oldr, "%s", old_root), sizeof oldr))
            bad = 1;
        else
            had_root = 1;
    }
    if (old_prod) {
        if (ovf(snprintf(oldp, sizeof oldp, "%s", old_prod), sizeof oldp))
            bad = 1;
        else
            had_prod = 1;
    }
    char sym[64], defp[4096], allp[4096], probep[4096], fx[4096], body[256], ob[8192];
    cbf_sym(sym, sizeof sym);
    if (ovf(snprintf(defp, sizeof defp, "%s/%s", root, k_cbf_def), sizeof defp)
        || ovf(snprintf(allp, sizeof allp, "%s/%s", root, k_cbf_allow), sizeof allp)
        || ovf(snprintf(probep, sizeof probep, "%s/core/probe.c", root), sizeof probep)
        || ovf(snprintf(fx, sizeof fx, "%s/engine/_xfixture.c", root), sizeof fx)
        || ovf(snprintf(body, sizeof body, "void %svoid) {}\n", sym), sizeof body)
        || csr_write(defp, body)
        || ovf(snprintf(body, sizeof body, "void f(void) { %s); }\n", sym), sizeof body)
        || csr_write(allp, body)
        || setenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST", root, 1) != 0)
        bad = 1;

    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check_no_new_coin_backfill_caller: clean — one allowed production caller") == NULL;

    if (ovf(snprintf(body, sizeof body, "void f(void) { %s); %s); }\n", sym, sym),
            sizeof body)
        || csr_write(allp, body))
        bad = 1;
    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "expected exactly 1 call in") == NULL
        || strstr(ob, "found 2") == NULL;

    if (ovf(snprintf(body, sizeof body, "void f(void) { %s); }\n", sym), sizeof body)
        || csr_write(allp, body)
        || ovf(snprintf(body, sizeof body, "void g(void) { %s); }\n", sym), sizeof body)
        || csr_write(probep, body))
        bad = 1;
    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "NEW production caller(s)") == NULL
        || strstr(ob, "core/probe.c:1") == NULL;
    (void)unlink(probep);

    (void)unlink(defp);
    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 2 || strstr(ob, "FATAL") == NULL;

    if (ovf(snprintf(body, sizeof body, "void %svoid) {}\n", sym), sizeof body)
        || csr_write(defp, body)
        || ovf(snprintf(body, sizeof body, "void x(void) { %s); }\n", sym), sizeof body)
        || csr_write(fx, body)
        || setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1) != 0)
        bad = 1;
    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check_no_new_coin_backfill_caller: clean — one allowed production caller") == NULL;
    (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "NEW production caller(s)") == NULL
        || strstr(ob, "engine/_xfixture.c:1") == NULL;

    fclose(cap);
    if (had_root)
        (void)setenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST", oldr, 1);
    else
        (void)unsetenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST");
    if (had_prod)
        (void)setenv("ZCL_LINT_PRODUCTION_SCAN", oldp, 1);
    else
        (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    (void)rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_no_new_coin_backfill_caller selftest\n", stderr);
    return st_ok(bad, "check_no_new_coin_backfill_caller selftest: OK\n");
}

static int mor_comment(const char *line)
{
    while (*line && isspace((unsigned char)*line))
        line++;
    return (line[0] == '/' && line[1] == '*')
        || line[0] == '*'
        || (line[0] == '/' && line[1] == '/');
}

struct mor_acc { regex_t *call; FILE *lines; int scanned; };

static int mor_on_file(const char *path, void *ctx)
{
    struct mor_acc *a = ctx;
    size_t n = strlen(path);
    if (n < 2 || path[n - 2] != '.'
        || (path[n - 1] != 'c' && path[n - 1] != 'h'))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int lineno = 0, rc = 0;
    while ((len = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->call, line, 0, NULL, 0) != 0)
            continue;
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (mor_comment(line))
            continue;
        a->scanned++;
        if (fprintf(a->lines, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    return fin(f, line, path, rc);
}

static int check_mind_owns_rebuild_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    regex_t call, allow;
    int cr = compile_pat(&call, REG_EXTENDED, "codeindex",
                         "_rebuild[[:space:]]*\\(", "", "");
    if (cr)
        return cr;
    cr = compile_pat(&allow, REG_EXTENDED,
                     "^(cognition/modules/codeindex/(src|include)/",
                     "|tools/mind/|tests/harness/src/test_codeindex)", "", "");
    if (cr) {
        regfree(&call);
        return cr;
    }
    FILE *hits = tmpfile(), *viol = tmpfile();
    if (!hits || !viol) {
        if (hits) fclose(hits);
        if (viol) fclose(viol);
        drop2(&call, &allow);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct mor_acc a = { .call = &call, .lines = hits, .scanned = 0 };
    int rc = each_zpath(k_ls_all, mor_on_file, &a);
    if (rc == 0)
        rc = gate_require_scanned(a.scanned, 4, "check-mind-owns-rebuild",
                                  "codeindex_rebuild's own module should always appear; check the pathspec.");
    int nviol = 0;
    if (rc == 0 && fseek(hits, 0, SEEK_SET) != 0)
        rc = die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while (rc == 0 && (n = getline(&line, &cap, hits)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (!line[0])
            continue;
        char *colon = strchr(line, ':');
        char save = 0;
        if (colon) {
            save = *colon;
            *colon = '\0';
        }
        int ok = colon && regexec(&allow, line, 0, NULL, 0) == 0;
        if (colon)
            *colon = save;
        if (ok)
            continue;
        nviol++;
        if (fprintf(viol, "%s\n", line) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    free(line);
    if (rc == 0 && ferror(hits))
        rc = die("z23-lint: read failed\n", "");
    if (rc == 0 && nviol) {
        if (fputs("check-mind-owns-rebuild: FAIL — codeindex_rebuild called outside the mind and the codeindex module\n",
                  stderr) < 0)
            rc = die("z23-lint: write failed\n", "");
        else if (fseek(viol, 0, SEEK_SET) != 0)
            rc = die("z23-lint: fseek failed\n", "");
        else
            rc = replay(viol);
        if (rc == 0
            && (fputs("  A query that rebuilds is a second writer racing the node resident.\n",
                      stderr) < 0
                || fputs("  Read the published generation with codeindex_open_readonly() and\n",
                         stderr) < 0
                || fputs("  refuse a stale one; the mind rebuilds. See docs/MIND.md.\n",
                         stderr) < 0))
            rc = die("z23-lint: write failed\n", "");
        if (rc == 0)
            rc = 1;
    } else if (rc == 0) {
        if (printf("check-mind-owns-rebuild: PASS — %d call site(s), all inside the codeindex module, tools/mind/, or that module's own tests\n",
                   a.scanned) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    fclose(hits);
    fclose(viol);
    drop2(&call, &allow);
    return rc;
}

static int check_mind_owns_rebuild_selftest(void)
{
    regex_t allow, call;
    int cr = compile_pat(&allow, REG_EXTENDED,
                         "^(cognition/modules/codeindex/(src|include)/",
                         "|tools/mind/|tests/harness/src/test_codeindex)", "", "");
    if (cr)
        return cr;
    cr = compile_pat(&call, REG_EXTENDED, "codeindex",
                     "_rebuild[[:space:]]*\\(", "", "");
    if (cr) {
        regfree(&allow);
        return cr;
    }
    int bad = 0;
    if (regexec(&allow, "cognition/modules/codeindex/src/codeindex_build.c", 0, NULL, 0) != 0
        || regexec(&allow, "tools/mind/mind_resident.c", 0, NULL, 0) != 0
        || regexec(&allow, "tests/harness/src/test_codeindex.c", 0, NULL, 0) != 0
        || regexec(&allow, "tools/command/native_code_command.c", 0, NULL, 0) == 0
        || regexec(&allow, "cognition/services/src/zcode_goal_context_service.c", 0, NULL, 0) == 0)
        bad = 1;
    char s1[80], s2[96];
    if (snprintf(s1, sizeof s1, "    if (!%s%s(ci))", "codeindex", "_rebuild")
            >= (int)sizeof s1
        || snprintf(s2, sizeof s2, " * Explicit %s%s() remains a forced recompute",
                    "codeindex", "_rebuild") >= (int)sizeof s2)
        bad = 1;
    else if (regexec(&call, s1, 0, NULL, 0) != 0
             || regexec(&call, s2, 0, NULL, 0) != 0)
        bad = 1;
    drop2(&allow, &call);
    return st_ok(bad, "check-mind-owns-rebuild selftest: OK\n");
}

static int sh_single_quote(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (cap < 3)
        return die("z23-lint: derived buffer overflow\n", "");
    out[used++] = '\'';
    for (const char *p = in; *p; p++) {
        if (*p == '\'') {
            if (used + 4 >= cap)
                return die("z23-lint: derived buffer overflow\n", "");
            out[used++] = '\'';
            out[used++] = '\\';
            out[used++] = '\'';
            out[used++] = '\'';
        } else {
            if (used + 2 > cap)
                return die("z23-lint: derived buffer overflow\n", "");
            out[used++] = *p;
        }
    }
    if (used + 2 > cap)
        return die("z23-lint: derived buffer overflow\n", "");
    out[used++] = '\'';
    out[used] = '\0';
    return 0;
}

/* The program's own absolute path, derived from argv[0] exactly the way the
 * shell gates derive SCRIPT_DIR — `cd "$(dirname "$0")" && pwd` — by entering
 * the directory and reading the working directory back. Every caller reaches
 * this binary through the tools/lint shim, which always passes a path with a
 * directory part; a bare name (found via PATH) is refused. No /proc read. */
static const char *g_lint_argv0;

static int lint_self_exe(char *buf, size_t cap)
{
    const char *a0 = g_lint_argv0;
    const char *slash = a0 ? strrchr(a0, '/') : NULL;
    char dir[4096], here[4096], there[4096];
    if (!slash || cap == 0)
        return die("z23-lint: cannot resolve executable path\n", "");
    size_t dlen = slash == a0 ? 1 : (size_t)(slash - a0);
    if (dlen >= sizeof dir || !getcwd(here, sizeof here))
        return die("z23-lint: cannot resolve executable path\n", "");
    memcpy(dir, a0, dlen);
    dir[dlen] = '\0';
    int ok = chdir(dir) == 0 && getcwd(there, sizeof there) != NULL;
    if (chdir(here) != 0)
        return die("z23-lint: cannot restore working directory\n", "");
    if (!ok)
        return die("z23-lint: cannot resolve executable path\n", "");
    int n = snprintf(buf, cap, "%s/%s", there, slash + 1);
    if (n < 0 || (size_t)n >= cap)
        return die("z23-lint: cannot resolve executable path\n", "");
    return 0;
}

static const char *env_or(const char *name, const char *fallback)
{
    const char *e = getenv(name);
    return (e && e[0]) ? e : fallback;
}

static int cic_digits(const char *s)
{
    if (!s || !s[0])
        return 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return 0;
    }
    return 1;
}

static unsigned long cic_u32(const char *s)
{
    unsigned long v = 0;
    for (; *s; s++)
        v = v * 10UL + (unsigned long)(*s - '0');
    return v;
}

static int cic_prefix_sed(const char *output)
{
    const char *p = output ? output : "";
    do {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (fputs("  ", stderr) < 0
            || fwrite(p, 1, n, stderr) != n
            || fputc('\n', stderr) == EOF)
            return die("z23-lint: write failed\n", "");
        if (!nl)
            break;
        p = nl + 1;
    } while (*p);
    return 0;
}

static int cic_prefix_log(const char *buf)
{
    if (!buf || !buf[0])
        return 0;
    return cic_prefix_sed(buf);
}

static void cic_take_az(const char *buf, const char *key, char *out, size_t cap)
{
    out[0] = '\0';
    size_t klen = strlen(key);
    for (const char *p = buf; (p = strstr(p, key)) != NULL; ) {
        p += klen;
        size_t n = 0;
        while (p[n] >= 'A' && p[n] <= 'Z')
            n++;
        if (p[n] != '"')
            continue;
        if (n >= cap)
            n = cap - 1;
        memcpy(out, p, n);
        out[n] = '\0';
        return;
    }
}

static void cic_take_num(const char *buf, const char *key, char *out, size_t cap)
{
    out[0] = '\0';
    size_t klen = strlen(key);
    for (const char *p = buf; (p = strstr(p, key)) != NULL; ) {
        p += klen;
        if (*p < '0' || *p > '9')
            continue;
        size_t n = 0;
        while (p[n] >= '0' && p[n] <= '9')
            n++;
        if (n >= cap)
            n = cap - 1;
        memcpy(out, p, n);
        out[n] = '\0';
        return;
    }
}

static void cic_take_q(const char *buf, const char *key, char *out, size_t cap)
{
    out[0] = '\0';
    size_t klen = strlen(key);
    const char *p = strstr(buf, key);
    if (!p)
        return;
    p += klen;
    size_t n = 0;
    while (p[n] && p[n] != '"')
        n++;
    if (n >= cap)
        n = cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
}

static int cic_ceiling(const char *path, char *out, size_t cap)
{
    out[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &lcap, f)) >= 0) {
        if (line[0] == '#')
            continue;
        char *p = line;
        while (*p && isspace((unsigned char)*p))
            p++;
        if (*p == '\0')
            continue;
        size_t i = 0;
        while (p[i] && !isspace((unsigned char)p[i]))
            i++;
        if (i >= cap)
            i = cap - 1;
        memcpy(out, p, i);
        out[i] = '\0';
        break;
    }
    return fin(f, line, path, rc);
}

static int cic_repo_root(char *buf, size_t cap)
{
    if (lint_self_exe(buf, cap))
        return 2;
    /* $ROOT/build/bin/z23-lint → $ROOT (executable dir, then two parents). */
    for (int i = 0; i < 3; i++) {
        char *slash = strrchr(buf, '/');
        if (!slash || slash == buf)
            return die("z23-lint: cannot resolve executable path\n", "");
        *slash = '\0';
    }
    return 0;
}

static int cic_invoke(const char *gate, int merge_err, char *out, size_t cap,
                      int *code)
{
    char exe[4096], quoted[8192], cmd[8192];
    if (lint_self_exe(exe, sizeof exe)
        || sh_single_quote(exe, quoted, sizeof quoted)
        || ovf(snprintf(cmd, sizeof cmd, "%s %s%s", quoted, gate,
                        merge_err ? " 2>&1" : ""), sizeof cmd))
        return 2;
    return capture_cmd(cmd, out, cap, code);
}

static int check_codeindex_coverage_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096], bin_def[4096], base_def[4096], ceiling[64];
    char qbin[8192], cmd[8192];
    static char captured[256 * 1024];
    char verdict[32], missing[32], summary[512];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (ovf(snprintf(bin_def, sizeof bin_def, "%s/build/bin/z23-dev", root),
            sizeof bin_def)
        || ovf(snprintf(base_def, sizeof base_def,
                        "%s/tools/lint/codeindex_coverage_baseline.txt", root),
               sizeof base_def))
        return 2;
    const char *bin = env_or("ZCL_CODEINDEX_COVERAGE_BIN", bin_def);
    const char *baseline = env_or("ZCL_CODEINDEX_COVERAGE_BASELINE", base_def);
    const char *source_root = env_or("ZCL_CODEINDEX_COVERAGE_ROOT", root);
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    if (access(bin, X_OK) != 0) {
        if (fprintf(stderr,
                    "check-codeindex-coverage: FATAL — missing executable %s\n",
                    bin) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    struct stat st;
    if (stat(baseline, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (fprintf(stderr,
                    "check-codeindex-coverage: FATAL — missing baseline %s\n",
                    baseline) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (cic_ceiling(baseline, ceiling, sizeof ceiling))
        return 2;
    if (!cic_digits(ceiling)) {
        if (fputs("check-codeindex-coverage: FATAL — baseline must contain one nonnegative integer\n",
                  stderr) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (setenv("ZCL_DEV_SOURCE_ROOT", source_root, 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    if (sh_single_quote(bin, qbin, sizeof qbin)
        || ovf(snprintf(cmd, sizeof cmd, "%s code coverage 2>&1", qbin),
               sizeof cmd))
        return 2;
    int code = 0;
    int rc = capture_cmd(cmd, captured, sizeof captured, &code);
    if (rc)
        return rc;
    if (code != 0) {
        if (fputs("check-codeindex-coverage: FATAL — code coverage could not measure the tree\n",
                  stderr) < 0)
            return die("z23-lint: write failed\n", "");
        rc = cic_prefix_sed(captured);
        return rc ? rc : 2;
    }
    cic_take_az(captured, "\"verdict\":\"", verdict, sizeof verdict);
    cic_take_num(captured, "\"missing_files\":", missing, sizeof missing);
    cic_take_q(captured, "\"summary\":\"", summary, sizeof summary);
    if (!cic_digits(missing)) {
        if (fputs("check-codeindex-coverage: FATAL — malformed code coverage reply\n",
                  stderr) < 0)
            return die("z23-lint: write failed\n", "");
        rc = cic_prefix_sed(captured);
        return rc ? rc : 2;
    }
    unsigned long miss_n = cic_u32(missing), ceil_n = cic_u32(ceiling);
    if (miss_n > ceil_n) {
        if (fprintf(stderr,
                    "check-codeindex-coverage: FAIL — %s; shrink-only ceiling=%s\n",
                    summary, ceiling) < 0)
            return die("z23-lint: write failed\n", "");
        rc = cic_prefix_sed(captured);
        return rc ? rc : 1;
    }
    if (strcmp(verdict, "GREEN") != 0 && miss_n == 0) {
        if (fputs("check-codeindex-coverage: FATAL — zero misses did not earn GREEN\n",
                  stderr) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    if (printf("check-codeindex-coverage: PASS — %s; shrink-only ceiling=%s\n",
               summary, ceiling) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int cic_st_fail(const char *msg, const char *log)
{
    if (fprintf(stderr, "check-codeindex-coverage: SELFTEST FAILED — %s\n",
                msg) < 0)
        return die("z23-lint: write failed\n", "");
    int rc = cic_prefix_log(log);
    return rc ? rc : 2;
}

static int check_codeindex_coverage_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-codeindex-coverage.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    char fixture[4096], srcdir[4096], ac[4096], missp[4096], basep[4096];
    static char logb[256 * 1024];
    int code = 0, rc, bad = 0;
    if (ovf(snprintf(fixture, sizeof fixture, "%s/repo", tmp), sizeof fixture)
        || ovf(snprintf(srcdir, sizeof srcdir, "%s/src", fixture), sizeof srcdir)
        || ovf(snprintf(ac, sizeof ac, "%s/a.c", srcdir), sizeof ac)
        || ovf(snprintf(missp, sizeof missp, "%s/missing.c", srcdir),
               sizeof missp)
        || ovf(snprintf(basep, sizeof basep, "%s/baseline", tmp), sizeof basep)
        || csr_write(ac, "int coverage_fixture(void) { return 23; }\n")
        || csr_write(basep, "0\n")) {
        (void)rap_rm_rf(tmp);
        return 2;
    }
    char dump[256], gitcmd[8192];
    if (strchr(fixture, '\'')) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: path too long: %s\n", fixture);
    }
    if (ovf(snprintf(gitcmd, sizeof gitcmd, "git -C '%s' init -q", fixture),
            sizeof gitcmd)
        || capture_cmd(gitcmd, dump, sizeof dump, &code) || code != 0
        || ovf(snprintf(gitcmd, sizeof gitcmd, "git -C '%s' add src/a.c",
                        fixture), sizeof gitcmd)
        || capture_cmd(gitcmd, dump, sizeof dump, &code) || code != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: command failed (%s)\n", "git");
    }
    if (setenv("ZCL_CODEINDEX_COVERAGE_ROOT", fixture, 1) != 0
        || setenv("ZCL_CODEINDEX_COVERAGE_BASELINE", basep, 1) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: setenv failed\n", "");
    }
    rc = cic_invoke("check-codeindex-coverage", 1, logb, sizeof logb, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 0) {
        bad = cic_st_fail("clean tracked source was not GREEN", logb);
        (void)rap_rm_rf(tmp);
        return bad;
    }
    if (csr_write(missp, "int planted_missing(void) { return 1; }\n")
        || ovf(snprintf(gitcmd, sizeof gitcmd, "git -C '%s' add src/missing.c",
                        fixture), sizeof gitcmd)
        || capture_cmd(gitcmd, dump, sizeof dump, &code) || code != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: command failed (%s)\n", "git");
    }
    if (unlink(missp) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: cannot open %s\n", missp);
    }
    rc = cic_invoke("check-codeindex-coverage", 1, logb, sizeof logb, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 1 || strstr(logb, "missing=1") == NULL) {
        bad = cic_st_fail("planted tracked omission was not named RED", logb);
        (void)rap_rm_rf(tmp);
        return bad;
    }
    if (ovf(snprintf(gitcmd, sizeof gitcmd,
                     "git -C '%s' rm -q --cached --ignore-unmatch src/missing.c",
                     fixture), sizeof gitcmd)
        || capture_cmd(gitcmd, dump, sizeof dump, &code) || code != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: command failed (%s)\n", "git");
    }
    rc = cic_invoke("check-codeindex-coverage", 1, logb, sizeof logb, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 0) {
        bad = cic_st_fail("removing the planted manifest row did not restore GREEN",
                          logb);
        (void)rap_rm_rf(tmp);
        return bad;
    }
    (void)rap_rm_rf(tmp);
    if (fputs("check-codeindex-coverage: SELFTEST PASS — clean and restored manifests are GREEN; one tracked missing file is RED\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int aae_fail(const char *msg)
{
    if (fprintf(stderr, "check_asan_adx_exception: FAIL — %s\n", msg) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static char *aae_trim(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
    return s;
}

static int aae_continued(const char *line)
{
    const char *p = line + strlen(line);
    while (p > line && (p[-1] == '\n' || p[-1] == '\r'))
        p--;
    while (p > line && isspace((unsigned char)p[-1]))
        p--;
    return p > line && p[-1] == '\\';
}

static int aae_is_override(const char *line, const char *name, const char **rest)
{
    static const char ov[] = "override";
    const char *p = line;
    size_t nl = strlen(name);
    if (strncmp(p, ov, sizeof ov - 1) != 0)
        return 0;
    p += sizeof ov - 1;
    if (!isspace((unsigned char)*p))
        return 0;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (strncmp(p, name, nl) != 0)
        return 0;
    p += nl;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (p[0] != ':' || p[1] != '=')
        return 0;
    *rest = p + 2;
    return 1;
}

static int aae_append(char *value, size_t cap, const char *tok)
{
    if (!tok[0])
        return 0;
    size_t used = strlen(value), add = strlen(tok);
    if (used) {
        if (used + 1 + add + 1 > cap)
            return die("z23-lint: derived buffer overflow\n", "");
        value[used++] = ' ';
        memcpy(value + used, tok, add + 1);
        return 0;
    }
    if (add + 1 > cap)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(value, tok, add + 1);
    return 0;
}

static int aae_read_var(const char *path, const char *name, char *value,
                        size_t cap)
{
    value[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int active = 0, rc = 0;
    while ((n = getline(&line, &lcap, f)) >= 0) {
        const char *body = line;
        if (!active) {
            if (!aae_is_override(line, name, &body))
                continue;
            active = 1;
        }
        int cont = aae_continued(body);
        if (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
            line[n - 1] = '\0';
            if (n > 1 && line[n - 2] == '\r')
                line[n - 2] = '\0';
        }
        if (cont) {
            size_t L = strlen((char *)body);
            while (L && isspace((unsigned char)body[L - 1]))
                L--;
            if (L && body[L - 1] == '\\')
                ((char *)body)[L - 1] = '\0';
        }
        char *tok = aae_trim((char *)body);
        if (aae_append(value, cap, tok)) {
            rc = 2;
            break;
        }
        if (!cont)
            break;
    }
    int fr = fin(f, line, path, rc);
    return fr ? fr : rc;
}

static int aae_has_needle(const char *path, const char *needle, int *found)
{
    *found = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (strstr(line, needle) != NULL) {
            *found = 1;
            break;
        }
    }
    return fin(f, line, path, rc);
}

static int aae_count_substr(const char *path, const char *needle, int *count)
{
    *count = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (strstr(line, needle) != NULL)
            (*count)++;
    }
    return fin(f, line, path, rc);
}

static int aae_count_re(const char *path, const regex_t *re, int *count)
{
    *count = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (regexec(re, line, 0, NULL, 0) == 0)
            (*count)++;
    }
    return fin(f, line, path, rc);
}

static int aae_require(const char *path, const char *needle)
{
    int found = 0;
    int rc = aae_has_needle(path, needle, &found);
    if (rc)
        return rc;
    if (found)
        return 0;
    char msg[8192];
    if (ovf(snprintf(msg, sizeof msg, "missing required Makefile wiring: %s",
                     needle), sizeof msg))
        return 2;
    return aae_fail(msg);
}

static int aae_copy(const char *src, const char *dst)
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
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    if (rc == 0 && ferror(in))
        rc = die("z23-lint: read failed: %s\n", src);
    if (fclose(out) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", dst);
    if (fclose(in) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", src);
    return rc;
}

static int aae_rewrite_first(const char *src, const char *dst, const char *from,
                             const char *to)
{
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
    int done = 0, rc = 0;
    while ((n = getline(&line, &cap, in)) >= 0) {
        char *hit = !done ? strstr(line, from) : NULL;
        if (hit) {
            size_t pre = (size_t)(hit - line);
            size_t fl = strlen(from), tl = strlen(to);
            if (fwrite(line, 1, pre, out) != pre
                || fwrite(to, 1, tl, out) != tl
                || fputs(hit + fl, out) < 0) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
            done = 1;
        } else if (fwrite(line, 1, (size_t)n, out) != (size_t)n) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    free(line);
    if (rc == 0 && ferror(in))
        rc = die("z23-lint: read failed: %s\n", src);
    if (fclose(out) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", dst);
    if (fclose(in) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", src);
    return rc;
}

static const char *aae_makefile(void)
{
    return env_or("ZCL_ASAN_ADX_MAKEFILE", "Makefile");
}

static int aae_check(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        char msg[8192];
        if (ovf(snprintf(msg, sizeof msg, "cannot read %s", path), sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    char sources[8192], flags[4096], common[8192], msg[8192];
    int rc = aae_read_var(path, "ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS",
                          sources, sizeof sources);
    if (rc)
        return rc;
    rc = aae_read_var(path, "ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS",
                      flags, sizeof flags);
    if (rc)
        return rc;
    rc = aae_read_var(path, "ASAN_COMMON_SAN_FLAGS", common, sizeof common);
    if (rc)
        return rc;
    if (strcmp(sources,
               "core/modules/sapling/src/bn254_accel.c "
               "core/modules/sapling/src/fr_avx512.c") != 0) {
        if (ovf(snprintf(msg, sizeof msg,
                         "exception source allowlist changed: '%s'", sources),
                sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    if (strcmp(flags, "-fomit-frame-pointer") != 0) {
        if (ovf(snprintf(msg, sizeof msg, "exception flags changed: '%s'",
                         flags), sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    if (strcmp(common,
               "-fsanitize=address,undefined -fno-omit-frame-pointer "
               "-fno-sanitize=alignment") != 0) {
        if (ovf(snprintf(msg, sizeof msg,
                         "general ASan/UBSan flags changed: '%s'", common),
                sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    static const char *const needles[] = {
        "TEST_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS := $(addprefix $(TEST_ASAN_OBJ_DIR)/,$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS:.c=.o))",
        "$(TEST_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS): TEST_ASAN_OBJECT_CFLAGS += $(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)",
        "DEV_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS := $(addprefix $(DEV_ASAN_OBJ_DIR)/,$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS:.c=.o))",
        "$(DEV_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS): DEV_ASAN_OBJECT_CFLAGS += $(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)",
    };
    for (size_t i = 0; i < sizeof needles / sizeof needles[0]; i++) {
        rc = aae_require(path, needles[i]);
        if (rc)
            return rc;
    }
    int epoch_count = 0;
    rc = aae_count_substr(path,
                          "adx-exception=$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS):$(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)",
                          &epoch_count);
    if (rc)
        return rc;
    if (epoch_count != 2) {
        if (ovf(snprintf(msg, sizeof msg,
                         "expected the test and dev ASan compile epochs to bind the exception; found %d binding(s)",
                         epoch_count), sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    regex_t re;
    rc = compile_pat(&re, REG_EXTENDED, "ASAN_COMMON_SAN_FLAGS",
                     "[[:space:]]*=", "", "");
    if (rc)
        return rc;
    int override_count = 0;
    rc = aae_count_re(path, &re, &override_count);
    regfree(&re);
    if (rc)
        return rc;
    if (override_count != 0) {
        if (ovf(snprintf(msg, sizeof msg,
                         "found %d recipe/caller override(s) of ASAN_COMMON_SAN_FLAGS",
                         override_count), sizeof msg))
            return 2;
        return aae_fail(msg);
    }
    rc = aae_require(path,
                     "TEST_ASAN_CFLAGS = $(filter-out -O3 $(ZCL_LTO_FLAG) -Werror,$(CACHED_CFLAGS)) -O1 -g -DZCL_TESTING \\");
    if (rc)
        return rc;
    return aae_require(path,
                       "DEV_ASAN_CFLAGS = $(filter-out -O3 $(ZCL_LTO_FLAG) -Werror,$(CACHED_CFLAGS)) $(ZCL_DEV_OPT) -g3 -DZCL_DEV_BUILD \\");
}

static int check_asan_adx_exception_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    int rc = aae_check(aae_makefile());
    if (rc)
        return rc;
    if (fputs("check_asan_adx_exception: clean — exactly two ASan ADX TUs omit frame pointers; sanitizer coverage and epoch bindings remain intact\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int check_asan_adx_exception_selftest(void)
{
    char root[4096];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    const char *mk = aae_makefile();
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-asan-adx-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    char copy[4096], nextp[4096];
    static char logb[256 * 1024];
    int code = 0, rc;
    if (ovf(snprintf(copy, sizeof copy, "%s/Makefile", tmp), sizeof copy)
        || ovf(snprintf(nextp, sizeof nextp, "%s/Makefile.next", tmp),
               sizeof nextp)
        || aae_copy(mk, copy)) {
        (void)rap_rm_rf(tmp);
        return 2;
    }
    if (setenv("ZCL_ASAN_ADX_MAKEFILE", copy, 1) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: setenv failed\n", "");
    }
    rc = cic_invoke("check-asan-adx-exception", 0, logb, sizeof logb, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 0) {
        (void)rap_rm_rf(tmp);
        return code;
    }
    static const char from[] = "core/modules/sapling/src/bn254_accel.c";
    static const char to[] =
        "core/modules/sapling/src/bn254_accel.c core/modules/sapling/src/unaudited_accel.c";
    if (aae_rewrite_first(copy, nextp, from, to) || rename(nextp, copy) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: write failed\n", "");
    }
    rc = cic_invoke("check-asan-adx-exception", 1, logb, sizeof logb, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code == 0) {
        (void)rap_rm_rf(tmp);
        return aae_fail("selftest expanded the exception allowlist but the gate passed");
    }
    if (strstr(logb, "exception source allowlist changed") == NULL) {
        (void)rap_rm_rf(tmp);
        return aae_fail("selftest failed for the wrong reason");
    }
    (void)rap_rm_rf(tmp);
    if (fputs("check_asan_adx_exception: selftest PASS — an allowlist expansion is rejected\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

enum { FFS_OWN_N = 7, FFS_VMAX = 1024, FFS_VLEN = 384 };
static const struct { const char *folder; const char *suffix; } k_ffs_own[] = {
    { "controllers", "controller" },
    { "services", "service" },
    { "models", "model" },
    { "views", "view" },
    { "jobs", "job" },
    { "supervisors", "supervisor" },
    { "conditions", "condition" },
};
static const char *const k_ffs_all[] = {
    "controller", "service", "model", "view", "job", "supervisor", "condition"
};

static const char *ffs_own_suffix(const char *folder)
{
    for (size_t i = 0; i < sizeof k_ffs_own / sizeof k_ffs_own[0]; i++)
        if (strcmp(k_ffs_own[i].folder, folder) == 0)
            return k_ffs_own[i].suffix;
    return NULL;
}

static int ffs_in_shapes(const char *folder, const char shapes[][RS_NAME], int n)
{
    for (int i = 0; i < n; i++)
        if (strcmp(shapes[i], folder) == 0)
            return 1;
    return 0;
}

static const char *ffs_foreign_shape(const char *b, const char *own)
{
    for (size_t i = 0; i < sizeof k_ffs_all / sizeof k_ffs_all[0]; i++) {
        const char *shape = k_ffs_all[i];
        if (strcmp(shape, own) == 0)
            continue;
        size_t sl = strlen(shape), bl = strlen(b);
        if (bl >= sl + 1 && b[bl - sl - 1] == '_' && strcmp(b + bl - sl, shape) == 0)
            return shape;
    }
    return NULL;
}

static int ffs_marker_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED,
                       "//[[:space:]]*suffix", "-ok:[A-Za-z0-9][A-Za-z0-9_-]*",
                       "", "");
}

static int ffs_buf_has_marker(const char *text, const regex_t *re)
{
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[4096];
        if (n < sizeof line) {
            memcpy(line, p, n);
            line[n] = '\0';
            if (regexec(re, line, 0, NULL, 0) == 0)
                return 1;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

static int ffs_file_has_marker(const char *path, const regex_t *re, int *hit)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        *hit = 0;
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    *hit = 0;
    while (!*hit && getline(&line, &cap, f) >= 0)
        if (regexec(re, line, 0, NULL, 0) == 0)
            *hit = 1;
    return fin(f, line, path, 0);
}

static int ffs_scan_room(const char *d, const char *own, const regex_t *re,
                         char v[][FFS_VLEN], int *nv)
{
    char src[4096];
    if (ovf(snprintf(src, sizeof src, "%s/src", d), sizeof src))
        return 2;
    struct dirent **names = NULL;
    int n = scandir(src, &names, NULL, alphasort);
    if (n < 0)
        return (errno == ENOENT || errno == ENOTDIR) ? 0
            : die("z23-lint: cannot scan %s\n", src);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            struct stat st;
            size_t nl = strlen(name);
            int k = snprintf(path, sizeof path, "%s/%s", src, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", src);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISREG(st.st_mode) && nl >= 2
                     && name[nl - 2] == '.' && name[nl - 1] == 'c') {
                char b[256];
                if (nl - 2 >= sizeof b)
                    rc = die("z23-lint: derived buffer overflow\n", "");
                else {
                    memcpy(b, name, nl - 2);
                    b[nl - 2] = '\0';
                    int marked = 0;
                    rc = ffs_file_has_marker(path, re, &marked);
                    if (rc == 0 && !marked) {
                        const char *shape = ffs_foreign_shape(b, own);
                        if (shape) {
                            if (*nv >= FFS_VMAX)
                                rc = die("z23-lint: derived buffer overflow\n", "");
                            else if (ovf(snprintf(v[*nv], FFS_VLEN,
                                    "%s ends in foreign-shape suffix _%s "
                                    "(this folder's shape: %s)",
                                    path, shape, own), FFS_VLEN))
                                rc = 2;
                            else
                                (*nv)++;
                        }
                    }
                }
            }
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int check_framework_filename_suffix_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int rc = rs_init();
    if (rc)
        return rc;
    for (int i = 0; i < g_n_shapes; i++) {
        if (ffs_own_suffix(g_shapes[i]))
            continue;
        fprintf(stderr, "check_framework_filename_suffix: FATAL — Makefile APP_DIRS has\n");
        fprintf(stderr, "  '%s' but the OWN[] suffix map has no entry for it.\n",
                g_shapes[i]);
        fprintf(stderr, "  Add its singular suffix; leaving it out silently exempts the\n");
        fprintf(stderr, "  whole app/%s/ tree from this gate.\n", g_shapes[i]);
        return 2;
    }
    for (size_t i = 0; i < sizeof k_ffs_own / sizeof k_ffs_own[0]; i++) {
        if (ffs_in_shapes(k_ffs_own[i].folder, g_shapes, g_n_shapes))
            continue;
        fprintf(stderr, "check_framework_filename_suffix: FATAL — OWN[] has '%s'\n",
                k_ffs_own[i].folder);
        fprintf(stderr, "  but the Makefile's APP_DIRS does not declare it.\n");
        return 2;
    }
    regex_t re;
    rc = ffs_marker_comp(&re);
    if (rc)
        return rc;
    static char viol[FFS_VMAX][FFS_VLEN];
    int nv = 0;
    char rooms[RS_MAX][RS_PATH];
    for (size_t i = 0; rc == 0 && i < sizeof k_ffs_own / sizeof k_ffs_own[0]; i++) {
        int nr = 0;
        rc = repo_shape_room_dirs(k_ffs_own[i].folder, rooms, RS_MAX, &nr);
        for (int r = 0; rc == 0 && r < nr; r++)
            rc = ffs_scan_room(rooms[r], k_ffs_own[i].suffix, &re, viol, &nv);
    }
    regfree(&re);
    if (rc)
        return rc;
    if (nv == 0)
        return puts("check_framework_filename_suffix: clean — no shape file carries a "
                    "foreign-shape filename suffix") < 0
                   ? die("z23-lint: write failed\n", "") : 0;
    if (printf("\ncheck_framework_filename_suffix: %d foreign-shape filename suffix "
               "violation(s)\n\n", nv) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < nv; i++)
        if (printf("  %s\n", viol[i]) < 0)
            return die("z23-lint: write failed\n", "");
    if (fputs("\nFix options:\n"
              "  1. Rename the file to its own shape's suffix or a bare entity name.\n"
              "  2. Move it to the folder whose shape its suffix names.\n"
              "  3. If the entity name legitimately ends in that shape word, add a\n"
              "     top-of-file marker '// suffix-ok:<tag>' explaining why.\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int check_framework_filename_suffix_selftest(void)
{
    regex_t re;
    int cr = ffs_marker_comp(&re);
    if (cr)
        return cr;
    int bad = 0;
    const char *shape = ffs_foreign_shape("foo_controller", "service");
    bad |= !(shape && strcmp(shape, "controller") == 0);
    bad |= ffs_foreign_shape("foo_service", "service") != NULL;
    bad |= ffs_foreign_shape("block", "model") != NULL;
    const char *marked = "/* header */\nint x;\n// suffix-ok:file_service\n";
    bad |= !ffs_buf_has_marker(marked, &re);
    bad |= ffs_buf_has_marker("int x;\nvoid f(void) {}\n", &re);
    bad |= !(ffs_buf_has_marker(marked, &re)
             && ffs_foreign_shape("file_service", "model") != NULL);
    char full[FFS_OWN_N][RS_NAME];
    for (int i = 0; i < FFS_OWN_N; i++)
        memcpy(full[i], k_ffs_own[i].folder, strlen(k_ffs_own[i].folder) + 1);
    int cover_own = 1, cover_shapes = 1;
    for (int i = 0; i < FFS_OWN_N; i++)
        if (!ffs_in_shapes(k_ffs_own[i].folder, full, FFS_OWN_N))
            cover_own = 0;
    for (int i = 0; i < FFS_OWN_N; i++)
        if (!ffs_own_suffix(full[i]))
            cover_shapes = 0;
    bad |= !cover_own || !cover_shapes;
    char miss[FFS_OWN_N][RS_NAME];
    for (int i = 0; i < FFS_OWN_N - 1; i++)
        memcpy(miss[i], k_ffs_own[i].folder, strlen(k_ffs_own[i].folder) + 1);
    int miss_cover = 1;
    for (int i = 0; i < FFS_OWN_N; i++)
        if (!ffs_in_shapes(k_ffs_own[i].folder, miss, FFS_OWN_N - 1))
            miss_cover = 0;
    bad |= miss_cover;
    char extra[FFS_OWN_N + 1][RS_NAME];
    for (int i = 0; i < FFS_OWN_N; i++)
        memcpy(extra[i], k_ffs_own[i].folder, strlen(k_ffs_own[i].folder) + 1);
    memcpy(extra[FFS_OWN_N], "widgets", 8);
    int extra_cover = 1;
    for (int i = 0; i < FFS_OWN_N + 1; i++)
        if (!ffs_own_suffix(extra[i]))
            extra_cover = 0;
    bad |= extra_cover;
    regfree(&re);
    return st_ok(bad, "check_framework_filename_suffix selftest: OK\n");
}

enum { SUS_DIRS = 32, SUS_STRAY_N = 256, SUS_STRAY_L = 512, SUS_TRACK = 2 * 1024 * 1024 };
static const char *const k_sus_dirs[] = {
    "core", "engine", "contexts", "cognition", "platform", "core", "adapters", "tools"
};

static int sus_split_ws(const char *s, char out[][RS_PATH], int max, int *n)
{
    *n = 0;
    while (*s) {
        while (*s && isspace((unsigned char)*s))
            s++;
        if (!*s)
            break;
        const char *e = s;
        while (*e && !isspace((unsigned char)*e))
            e++;
        size_t len = (size_t)(e - s);
        if (*n >= max || len >= RS_PATH)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(out[*n], s, len);
        out[*n][len] = '\0';
        (*n)++;
        s = e;
    }
    return 0;
}

static int sus_has_seg(const char *path, const char *seg)
{
    char needle[192];
    int n = snprintf(needle, sizeof needle, "/%s/", seg);
    if (n < 0 || (size_t)n >= sizeof needle)
        return 0;
    if (strstr(path, needle) != NULL)
        return 1;
    size_t sl = strlen(seg);
    return strncmp(path, seg, sl) == 0 && path[sl] == '/';
}

static int sus_fix_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED, ".*/_[^/]*fixture[^/]*\\.", "[ch]$", "", "");
}

static int sus_excluded(const char *path, const regex_t *fixre)
{
    if (sus_has_seg(path, k_planted) || sus_has_seg(path, "build")
        || sus_has_seg(path, "vendor") || sus_has_seg(path, "test-tmp"))
        return 1;
    return regexec(fixre, path, 0, NULL, 0) == 0;
}

static int sus_in_set(const char *buf, size_t used, const char *path)
{
    size_t n = strlen(path);
    for (size_t i = 0; i < used; ) {
        size_t m = strlen(buf + i);
        if (m == n && memcmp(buf + i, path, n) == 0)
            return 1;
        i += m + 1;
    }
    return 0;
}

struct sus_track { char *buf; size_t cap, used; };
static int sus_on_track(const char *path, void *ctx)
{
    struct sus_track *t = ctx;
    size_t n = strlen(path) + 1;
    if (t->used + n > t->cap)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(t->buf + t->used, path, n);
    t->used += n;
    return 0;
}

struct sus_acc {
    const regex_t *fixre;
    const char *track;
    size_t tused;
    char (*stray)[SUS_STRAY_L];
    int nstray, ncand;
};

static int sus_scan(const char *path, void *ctx)
{
    struct sus_acc *a = ctx;
    if (sus_excluded(path, a->fixre))
        return 0;
    a->ncand++;
    if (sus_in_set(a->track, a->tused, path))
        return 0;
    size_t n = strlen(path);
    if (a->nstray >= SUS_STRAY_N || n >= SUS_STRAY_L)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(a->stray[a->nstray], path, n + 1);
    a->nstray++;
    return 0;
}

static int sus_seen(const char seen[][RS_PATH], int n, const char *d)
{
    for (int i = 0; i < n; i++)
        if (strcmp(seen[i], d) == 0)
            return 1;
    return 0;
}

static int check_no_stray_untracked_source_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char scan[SUS_DIRS][RS_PATH];
    int nd = 0, rc = 0;
    const char *env = getenv("ZCL_STRAY_SCAN_DIRS_FOR_TEST");
    if (env && env[0])
        rc = sus_split_ws(env, scan, SUS_DIRS, &nd);
    else {
        for (size_t i = 0; i < sizeof k_sus_dirs / sizeof k_sus_dirs[0]; i++) {
            size_t n = strlen(k_sus_dirs[i]);
            memcpy(scan[nd], k_sus_dirs[i], n + 1);
            nd++;
        }
    }
    if (rc)
        return rc;
    char exist[SUS_DIRS][RS_PATH];
    int ne = 0;
    for (int i = 0; i < nd; i++) {
        struct stat st;
        if (stat(scan[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            size_t n = strlen(scan[i]);
            if (ne >= SUS_DIRS || n >= RS_PATH)
                return die("z23-lint: derived buffer overflow\n", "");
            memcpy(exist[ne], scan[i], n + 1);
            ne++;
        }
    }
    rc = gate_require_scanned(ne, 1, "check-no-stray-untracked-source",
                              "none of the scanned root dirs exist — layout changed?");
    if (rc)
        return rc;
    regex_t fixre;
    rc = sus_fix_comp(&fixre);
    if (rc)
        return rc;
    char lscmd[8192];
    int k = snprintf(lscmd, sizeof lscmd, "git ls-files -z --");
    if (ovf(k, sizeof lscmd)) {
        regfree(&fixre);
        return 2;
    }
    size_t used = (size_t)k;
    for (int i = 0; i < ne; i++) {
        k = snprintf(lscmd + used, sizeof lscmd - used, " %s", exist[i]);
        if (ovf(k, sizeof lscmd - used)) {
            regfree(&fixre);
            return 2;
        }
        used += (size_t)k;
    }
    static char track[SUS_TRACK];
    struct sus_track t = { .buf = track, .cap = sizeof track };
    rc = each_zpath(lscmd, sus_on_track, &t);
    if (rc) {
        regfree(&fixre);
        return rc;
    }
    static char stray[SUS_STRAY_N][SUS_STRAY_L];
    struct sus_acc a = {
        .fixre = &fixre, .track = track, .tused = t.used, .stray = stray
    };
    char walked[SUS_DIRS][RS_PATH];
    int nw = 0;
    for (int i = 0; rc == 0 && i < ne; i++) {
        if (sus_seen(walked, nw, exist[i]))
            continue;
        size_t n = strlen(exist[i]);
        if (nw >= SUS_DIRS || n >= RS_PATH)
            rc = die("z23-lint: derived buffer overflow\n", "");
        else {
            memcpy(walked[nw], exist[i], n + 1);
            nw++;
            rc = walk_src(exist[i], 1, sus_scan, &a);
        }
    }
    regfree(&fixre);
    if (rc)
        return rc;
    if (a.nstray > 0) {
        if (fprintf(stderr, "FAIL: %d untracked stray file(s) under scanned source dirs\n",
                    a.nstray) < 0
            || fputs("  These are NOT code violations — they are files git does not track,\n"
                     "  most often leftovers from a crashed agent or an abandoned worktree\n"
                     "  (files matching the lint-gate selftest fixture naming convention,\n"
                     "  _*fixture*.c, are excluded from this check — see the header comment).\n"
                     "  Delete them (or 'git add' if intentional new source):\n",
                     stderr) < 0)
            return die("z23-lint: write failed\n", "");
        for (int i = 0; i < a.nstray; i++)
            if (fprintf(stderr, "    %s [untracked stray file -- not a code violation]\n",
                        a.stray[i]) < 0)
                return die("z23-lint: write failed\n", "");
        return 1;
    }
    char joined[2048];
    size_t ju = 0;
    joined[0] = '\0';
    for (int i = 0; i < ne; i++) {
        k = snprintf(joined + ju, sizeof joined - ju, "%s%s", i ? " " : "", exist[i]);
        if (ovf(k, sizeof joined - ju))
            return 2;
        ju += (size_t)k;
    }
    return printf("[check_no_stray_untracked_source] scanned %d file(s) under %s; "
                  "0 untracked strays\n", a.ncand, joined) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int check_no_stray_untracked_source_selftest(void)
{
    regex_t re;
    int cr = sus_fix_comp(&re);
    if (cr)
        return cr;
    int bad = 0;
    bad |= !sus_excluded("tools/lint/fixtures/planted/foo.c", &re);
    bad |= !sus_excluded("x/tools/lint/fixtures/planted/foo.c", &re);
    bad |= !sus_excluded("core/foo/build/x.c", &re);
    bad |= !sus_excluded("engine/vendor/x.c", &re);
    bad |= !sus_excluded("core/test-tmp/x.c", &re);
    bad |= !sus_excluded("core/src/_abfixture.c", &re);
    bad |= sus_excluded("core/consensus/src/foo.c", &re);
    bad |= sus_excluded("core/.claude/foo.c", &re);
    char set[32];
    memcpy(set, "core/a.c", 9);
    memcpy(set + 9, "core/b.c", 9);
    bad |= !sus_in_set(set, 18, "core/a.c");
    bad |= sus_in_set(set, 18, "core/missing.c");
    regfree(&re);
    return st_ok(bad, "check_no_stray_untracked_source selftest: OK\n");
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
    { "check-no-shellouts", check_no_shellouts_run, check_no_shellouts_selftest },
    { "check-command-contract", check_command_contract_run, check_command_contract_selftest },
    { "check-no-writer-below-sealed-frontier", check_no_writer_below_sealed_frontier_run,
      check_no_writer_below_sealed_frontier_selftest },
    { "check-no-stray-root-files", check_no_stray_root_files_run,
      check_no_stray_root_files_selftest },
    { "check-proc-self-shim", check_proc_self_shim_run, check_proc_self_shim_selftest },
    { "check-simd-os-support", check_simd_os_support_run, check_simd_os_support_selftest },
    { "check-c23-only", check_c23_only_run, check_c23_only_selftest },
    { "check-hotswap-dev-only", check_hotswap_dev_only_run, check_hotswap_dev_only_selftest },
    { "check-no-api-keys", check_no_api_keys_run, check_no_api_keys_selftest },
    { "check-error-doc-refs", check_error_doc_refs_run, check_error_doc_refs_selftest },
    { "check-core-seal-root-mirror", check_core_seal_root_mirror_run,
      check_core_seal_root_mirror_selftest },
    { "check-peer-floor-single-source", check_peer_floor_single_source_run,
      check_peer_floor_single_source_selftest },
    { "check-proof-server-pin", check_proof_server_pin_run,
      check_proof_server_pin_selftest },
    { "check-tu-random-seed", check_tu_random_seed_run,
      check_tu_random_seed_selftest },
    { "check-no-retired-agent-protocol", check_no_retired_agent_protocol_run,
      check_no_retired_agent_protocol_selftest },
    { "check-stopwatch-skip-detector", check_stopwatch_skip_detector_run,
      check_stopwatch_skip_detector_selftest },
    { "check-no-warning-suppression", check_no_warning_suppression_run,
      check_no_warning_suppression_selftest },
    { "check-privileged-transition-receipt", check_privileged_transition_receipt_run,
      check_privileged_transition_receipt_selftest },
    { "check-no-new-coin-backfill-caller", check_no_new_coin_backfill_caller_run,
      check_no_new_coin_backfill_caller_selftest },
    { "check-mind-owns-rebuild", check_mind_owns_rebuild_run,
      check_mind_owns_rebuild_selftest },
    { "check-codeindex-coverage", check_codeindex_coverage_run,
      check_codeindex_coverage_selftest },
    { "check-asan-adx-exception", check_asan_adx_exception_run,
      check_asan_adx_exception_selftest },
    { "check-framework-filename-suffix", check_framework_filename_suffix_run,
      check_framework_filename_suffix_selftest },
    { "check-no-stray-untracked-source", check_no_stray_untracked_source_run,
      check_no_stray_untracked_source_selftest },
};

int main(int argc, char **argv)
{
    g_lint_argv0 = argc > 0 ? argv[0] : NULL;
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
