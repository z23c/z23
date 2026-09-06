/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — small pattern-matching lint gates of the C23 lint
 * runtime (check-no-python, check-malloc, check-dev-proof-native-fast-path,
 * check-before-save-hooks, check-pthread-create, check-silent-error-returns,
 * check-no-gnu-va-args, check-blob-read-bounds, check-wire-harness-security-gate,
 * check-tor-dial-prewarm).
 */

/*
 * Gates: check-no-python, check-malloc, check-dev-proof-native-fast-path, check-before-save-hooks, check-pthread-create, check-silent-error-returns, check-no-gnu-va-args, check-blob-read-bounds, check-posix-ere-only, check-wire-harness-security-gate, check-tor-dial-prewarm
 * Default landing spot for a FUTURE gate port: a filesystem-tree-walking
 * gate (walk_src/clock_walk/repo_shape_room_dirs) joins gate_tree_walk.c;
 * a git-tracked-enumeration gate (each_zpath/each_zpath_st) joins whichever
 * of gate_git_scan_a.c/gate_git_scan_b.c is currently smaller by wc -l;
 * a proof/landing/receipt-shaped gate joins gate_landing_proof.c; a
 * build-flag/CI-toggle-shaped gate joins gate_build_config.c; only once
 * EVERY existing family is within ~200 lines of the ~1500 cap does a new
 * gate warrant a new family file — name it for its own subject the same
 * way the seven above are named for theirs.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

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


int check_no_python_run(int argc, char **argv)
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

int check_no_python_selftest(void)
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

int check_malloc_run(int argc, char **argv)
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

int check_malloc_selftest(void)
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

int check_dev_proof_native_fast_path_run(int argc, char **argv)
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

int check_dev_proof_native_fast_path_selftest(void)
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

int check_before_save_hooks_run(int argc, char **argv)
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

int check_before_save_hooks_selftest(void)
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

int check_pthread_create_run(int argc, char **argv)
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

int check_pthread_create_selftest(void)
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

int check_silent_error_returns_run(int argc, char **argv)
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

int check_silent_error_returns_selftest(void)
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

int check_no_gnu_va_args_run(int argc, char **argv)
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

int check_no_gnu_va_args_selftest(void)
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

/* check-blob-read-bounds — port of the awk state machine from the original
 * tools/lint/check_blob_read_bounds.sh (now a shim). Fixed-size SQLite blob
 * reads in app models must use AR_READ_BLOB or prove the SQLite blob length
 * before memcpy: a short BLOB at rest must never be copied as 16/32/43/etc.
 * bytes from sqlite3_column_blob(). Per file: a variable assigned from
 * sqlite3_column_blob is tracked for 16 lines (then forgotten); a
 * sqlite3_column_bytes / AR_COL_BYTES call guards every tracked variable and
 * opens a 6-line nearby-guard window (the guard line itself plus five); an
 * AR_READ_BLOB line is skipped whole. A memcpy with a fixed copy length
 * ([0-9]+ or sizeof(...)) trips when it reads sqlite3_column_blob directly
 * with no nearby guard, or reads a tracked, unguarded blob variable.
 *
 * Two deliberate choices:
 *  - when one memcpy line references several tracked blob variables, the
 *    original picks one through awk's unspecified associative-array
 *    iteration order; no two awk implementations agree there. This port
 *    checks the earliest-tracked matching variable.
 *  - awk tracks unbounded variables; this port keeps 32 live variables of
 *    up to 63 chars per file and dies loudly past that (the runtime's
 *    bounded-buffer style) instead of silently changing verdicts.
 * Parity note: the shell original's engine/models/src glob sorts in the
 * user locale, so run() calls setlocale(LC_ALL, "") before
 * scandir/alphasort to keep multi-file violation order byte-identical. */

#define BRB_LIVE 32
#define BRB_NAME 64

struct brb_var { char name[BRB_NAME]; int guarded; int age; };

struct brb {
    regex_t re_ar, re_bytes, re_assign, re_memcpy, re_direct, re_fixlen;
    struct brb_var v[BRB_LIVE];
    int n, guard;
};

static void brb_free(struct brb *b, int n)
{
    regex_t *re[] = { &b->re_ar, &b->re_bytes, &b->re_assign,
                      &b->re_memcpy, &b->re_direct, &b->re_fixlen };
    for (int i = 0; i < n && i < 6; i++)
        regfree(re[i]);
}

static int brb_compile(struct brb *b)
{
    static const char *const pat[] = {
        "AR_READ_" "BLOB[ \t]*\\(",
        "(sqlite3_column_" "bytes|AR_COL_" "BYTES)[ \t]*\\(",
        "[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*(\\([^)]*\\)[ \t]*)?"
            "sqlite3_column_" "blob[ \t]*\\(",
        "mem" "cpy[ \t]*\\(",
        "sqlite3_column_" "blob[ \t]*\\(",
        ",[ \t]*(\\(?size_t\\)?[ \t]*)?([0-9]+|sizeof[ \t]*\\([^;]*\\))"
            "[ \t]*\\)[ \t]*;[ \t]*(//.*)?$",
    };
    regex_t *re[] = { &b->re_ar, &b->re_bytes, &b->re_assign,
                      &b->re_memcpy, &b->re_direct, &b->re_fixlen };
    for (int i = 0; i < 6; i++) {
        int err = regcomp(re[i], pat[i], REG_EXTENDED);
        if (err) {
            brb_free(b, i);
            return reg_fail(re[i], err);
        }
    }
    b->n = 0;
    b->guard = 0;
    return 0;
}

/* awk's [A-Za-z0-9_] classes, spelled out so the answer cannot depend on
 * the locale setlocale() just installed. */
static int brb_word(int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '_';
}

static int brb_uses(const char *line, const char *var, size_t vlen)
{
    for (const char *p = line; (p = strstr(p, var)) != NULL; p++) {
        int left = p == line || !brb_word((unsigned char)p[-1]);
        const char *q = p + vlen;
        int right = *q == '\0' || !brb_word((unsigned char)*q);
        if (left && right)
            return 1;
    }
    return 0;
}

/* One scanned line (newline stripped). Returns 1 and fills msg on a
 * violation, 0 when clean, 2 on an internal error. */
static int brb_line(struct brb *b, const char *line, char *msg, size_t cap)
{
    for (int i = 0; i < b->n; i++) {
        if (++b->v[i].age > 16) {
            memmove(&b->v[i], &b->v[i + 1],
                    (size_t)(b->n - i - 1) * sizeof b->v[0]);
            b->n--;
            i--;
        }
    }
    if (b->guard > 0)
        b->guard--;
    if (regexec(&b->re_ar, line, 0, NULL, 0) == 0)
        return 0;
    if (regexec(&b->re_bytes, line, 0, NULL, 0) == 0) {
        b->guard = 6;
        for (int i = 0; i < b->n; i++)
            b->v[i].guarded = 1;
    }
    regmatch_t m[1];
    if (regexec(&b->re_assign, line, 1, m, 0) == 0) {
        const char *h = line + m[0].rm_so;
        size_t vl = 0;
        while (brb_word((unsigned char)h[vl]))
            vl++;
        if (vl == 0 || vl >= BRB_NAME)
            return die("z23-lint: blob-var overflow\n", "");
        int idx = -1;
        for (int i = 0; i < b->n; i++) {
            if (strlen(b->v[i].name) == vl && memcmp(b->v[i].name, h, vl) == 0) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            if (b->n >= BRB_LIVE)
                return die("z23-lint: blob-var overflow\n", "");
            idx = b->n++;
        }
        memcpy(b->v[idx].name, h, vl);
        b->v[idx].name[vl] = '\0';
        b->v[idx].guarded = 0;
        b->v[idx].age = 0;
    }
    if (regexec(&b->re_memcpy, line, 0, NULL, 0) != 0)
        return 0;
    if (regexec(&b->re_direct, line, 0, NULL, 0) == 0) {
        if (b->guard == 0 && regexec(&b->re_fixlen, line, 0, NULL, 0) == 0) {
            int k = snprintf(msg, cap, "%s",
                "mem" "cpy directly from sqlite3_column_"
                "blob without nearby column_" "bytes guard");
            return ovf(k, cap) ? 2 : 1;
        }
        return 0;
    }
    for (int i = 0; i < b->n; i++) {
        if (!brb_uses(line, b->v[i].name, strlen(b->v[i].name)))
            continue;
        if (!b->v[i].guarded && b->guard == 0
            && regexec(&b->re_fixlen, line, 0, NULL, 0) == 0) {
            int k = snprintf(msg, cap,
                "mem" "cpy from sqlite3_column_" "blob variable %s without "
                "column_" "bytes guard", b->v[i].name);
            return ovf(k, cap) ? 2 : 1;
        }
        break;
    }
    return 0;
}

static int brb_scan_file(struct brb *b, const char *path, int *fail)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    b->n = 0;
    b->guard = 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        char msg[192];
        int v = brb_line(b, line, msg, sizeof msg);
        if (v == 2) {
            rc = 2;
            break;
        }
        if (v == 1) {
            *fail = 1;
            if (fprintf(stdout, "%s:%d: %s\n", path, lineno, msg) < 0) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
        }
    }
    return fin(f, line, path, rc);
}

int check_blob_read_bounds_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    setlocale(LC_ALL, ""); /* bash globs sort in the user locale; alphasort
                            * must too or multi-file violation order drifts */
    struct brb b;
    int rc = brb_compile(&b);
    if (rc)
        return rc;
    struct dirent **names = NULL;
    int nd = scandir("engine/models/src", &names, NULL, alphasort);
    if (nd < 0 && errno == ENOENT)
        nd = 0; /* nullglob: a missing scan dir is an empty file list */
    else if (nd < 0)
        rc = die("z23-lint: cannot scan %s\n", "engine/models/src");
    int fail = 0;
    for (int i = 0; i < nd; i++) {
        const char *nm = names[i]->d_name;
        size_t nl = strlen(nm);
        if (rc == 0 && nl > 2 && nm[0] != '.' && strcmp(nm + nl - 2, ".c") == 0) {
            char path[320];
            int k = snprintf(path, sizeof path, "engine/models/src/%s", nm);
            if (ovf(k, sizeof path))
                rc = 2;
            else if (!lint_path_is_excluded(path))
                rc = brb_scan_file(&b, path, &fail);
        }
        free(names[i]);
    }
    free(names);
    brb_free(&b, 6);
    if (rc)
        return rc;
    if (fail) {
        if (fputs("FAIL: unsafe fixed-size sqlite3_column_" "blob mem" "cpy "
                  "in app models.\n"
                  "      Use AR_READ_" "BLOB(stmt,col,dest,len), or guard with "
                  "sqlite3_column_" "bytes first.\n", stderr) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return printf("check_blob_read_bounds: clean — app model blob mem"
                  "cpy sites are length-guarded\n") < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int brb_st_line(struct brb *b, const char *line, int want,
                       const char *want_msg)
{
    char msg[192];
    int v = brb_line(b, line, msg, sizeof msg);
    if (v != want || (want == 1 && strcmp(msg, want_msg) != 0)) {
        fprintf(stderr, "check_blob_read_bounds selftest: want %d got %d: %s\n",
                want, v, line);
        return 1;
    }
    return 0;
}

int check_blob_read_bounds_selftest(void)
{
    struct brb b;
    int cr = brb_compile(&b);
    if (cr)
        return cr;
    static const char m_direct[] =
        "mem" "cpy directly from sqlite3_column_"
        "blob without nearby column_" "bytes guard";
    static const char m_var[] =
        "mem" "cpy from sqlite3_column_" "blob variable row without column_"
        "bytes guard";
    const char *direct = "    mem" "cpy(dest, sqlite3_column_"
        "blob(stmt, 0), 32);";
    const char *assign = "    const void *row = sqlite3_column_"
        "blob(stmt, 1);";
    const char *guard = "    int n = sqlite3_column_" "bytes(stmt, 1);";
    const char *var_cp = "    mem" "cpy(dest, row, 43);";
    const char *filler = "    total += 1;";
    int bad = 0;
    /* Direct unguarded fixed-size read trips. */
    bad |= brb_st_line(&b, direct, 1, m_direct);
    /* sizeof(...) and (size_t) casts and trailing comments are fixed too. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, "    mem" "cpy(dest, sqlite3_column_"
                       "blob(stmt, 0), sizeof(dest));",
                       1, m_direct);
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, "    mem" "cpy(dest, sqlite3_column_"
                       "blob(stmt, 0), (size_t)32); // hash",
                       1, m_direct);
    /* A variable length or sizeof without parens is not a fixed copy. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, "    mem" "cpy(dest, sqlite3_column_"
                       "blob(stmt, 0), len);", 0, NULL);
    bad |= brb_st_line(&b, "    mem" "cpy(dest, sqlite3_column_"
                       "blob(stmt, 0), sizeof *dest);",
                       0, NULL);
    /* A column_bytes call guards the line itself and the next five. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, guard, 0, NULL);
    bad |= brb_st_line(&b, direct, 0, NULL);
    /* Window expiry: guard line + five lines guarded, the seventh trips. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, guard, 0, NULL);
    for (int i = 0; i < 4; i++)
        bad |= brb_st_line(&b, filler, 0, NULL);
    bad |= brb_st_line(&b, direct, 0, NULL);   /* sixth line after the guard */
    bad |= brb_st_line(&b, direct, 1, m_direct); /* seventh: window closed */
    /* A tracked blob variable trips a later fixed-size memcpy. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, assign, 0, NULL);
    bad |= brb_st_line(&b, var_cp, 1, m_var);
    /* A casted assignment is still a blob assignment. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, "    const void *row = (const void *)sqlite3_column_"
                       "blob(stmt, 1);",
                       0, NULL);
    bad |= brb_st_line(&b, var_cp, 1, m_var);
    /* column_bytes marks every tracked variable guarded, past the window. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, assign, 0, NULL);
    bad |= brb_st_line(&b, guard, 0, NULL);
    for (int i = 0; i < 6; i++)
        bad |= brb_st_line(&b, filler, 0, NULL);
    bad |= brb_st_line(&b, var_cp, 0, NULL);
    /* Re-assigning the variable drops its guarded mark. */
    bad |= brb_st_line(&b, assign, 0, NULL);
    bad |= brb_st_line(&b, var_cp, 1, m_var);
    /* The variable is forgotten 16 lines after its assignment. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, assign, 0, NULL);
    for (int i = 0; i < 15; i++)
        bad |= brb_st_line(&b, filler, 0, NULL);
    bad |= brb_st_line(&b, var_cp, 1, m_var);   /* age 16: still tracked */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, assign, 0, NULL);
    for (int i = 0; i < 16; i++)
        bad |= brb_st_line(&b, filler, 0, NULL);
    bad |= brb_st_line(&b, var_cp, 0, NULL);   /* age 17: forgotten */
    /* `==` is not a blob assignment; the variable stays unknown. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, "    if (row == sqlite3_column_"
                       "blob(stmt, 1))", 0, NULL);
    bad |= brb_st_line(&b, var_cp, 0, NULL);
    /* Non-boundary lookalikes (arrow, row2) do not name the variable. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, assign, 0, NULL);
    bad |= brb_st_line(&b, "    mem" "cpy(dest, arrow, 43);", 0, NULL);
    bad |= brb_st_line(&b, "    mem" "cpy(dest, row2, 43);", 0, NULL);
    /* An AR_READ_BLOB line is skipped whole, memcpy and all. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, "    if (AR_READ_" "BLOB(stmt, 0, dest, 32)) mem"
                       "cpy(t, s, 32);",
                       0, NULL);
    /* AR_COL_BYTES is a guard too. */
    b.n = 0; b.guard = 0;
    bad |= brb_st_line(&b, assign, 0, NULL);
    bad |= brb_st_line(&b, "    if (AR_COL_" "BYTES(stmt, 1) != 43) return 0;",
                       0, NULL);
    bad |= brb_st_line(&b, var_cp, 0, NULL);
    brb_free(&b, 6);
    return st_ok(bad, "check_blob_read_bounds selftest: OK\n");
}


/* GNU ERE extension letters after a backslash. The two-byte bigram is never
 * written adjacent in this file: the match pattern and the --selftest fixture
 * are joined at runtime (same fragment technique as so_comp / the
 * check_no_shellouts selftest fixture). */
static int ere_gnu_letter(unsigned char c)
{
    return c == 'b' || c == 'B' || c == 'w' || c == 'W'
        || c == 's' || c == 'S' || c == 'd' || c == 'D'
        || c == '<' || c == '>';
}

static int ere_letter_at(const char *line)
{
    for (const char *p = line; *p; p++) {
        if ((unsigned char)*p == '\\' && ere_gnu_letter((unsigned char)p[1]))
            return (unsigned char)p[1];
    }
    return 0;
}

static int ere_comp(regex_t *re)
{
    char pat[32];
    int n = snprintf(pat, sizeof pat, "%s%s", "\\\\[", "bBwWsSdD<>]");
    if (n < 0 || (size_t)n >= sizeof pat)
        return die("z23-lint: pattern buffer overflow\n", "");
    return reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int ere_should_report(const char *path, const char *line)
{
    if (lint_path_is_excluded(path))
        return 0;
    if (strstr(line, "// posix-ere-ok:") != NULL)
        return 0;
    return ere_letter_at(line);
}

struct ere_acc { int hits; };

static int scan_ere(const char *path, void *ctx)
{
    struct ere_acc *a = ctx;
    if (lint_path_is_excluded(path))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        int x = ere_should_report(path, line);
        if (!x)
            continue;
        if (fprintf(stderr, "%s:%d: \\%c\n", path, lineno, x) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        a->hits++;
    }
    return fin(f, line, path, rc);
}

int check_posix_ere_only_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct ere_acc a = { .hits = 0 };
    int rc = walk_src("tools", 0, scan_ere, &a);
    if (rc)
        return rc;
    if (a.hits) {
        if (fputs("check-posix-ere-only: replace a GNU regex-extension escape "
                  "with a POSIX ERE boundary form - (^|[^[:alnum:]_]) before, "
                  "([^[:alnum:]_]|$) after\n", stderr) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    return printf("[check_posix_ere_only] 0 violation(s) found\n") < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_posix_ere_only_selftest(void)
{
    regex_t re;
    int cr = ere_comp(&re);
    if (cr)
        return cr;
    char hit[72], clean[72], marked[96];
    if (ovf(snprintf(hit, sizeof hit, "regcomp(&re, \"%s%s", "\\",
                     "b\", REG_EXTENDED);"), sizeof hit)
        || ovf(snprintf(clean, sizeof clean, "%s",
                        "regcomp(&re, \"[[:space:]]+\", REG_EXTENDED);"),
               sizeof clean)
        || ovf(snprintf(marked, sizeof marked, "%s // posix-ere-ok:selftest",
                        hit), sizeof marked)) {
        regfree(&re);
        return 2;
    }
    const char *t = "check_posix_ere_only";
    const char *real = "tools/lint/lintc/x.c";
    const char *excl = "tools/lint/fixtures/planted/x.c";
    int bad = want(t, &re, hit, 1) | want(t, &re, clean, 0) | want(t, &re, marked, 1)
            | (ere_letter_at(hit) != 'b') | (ere_letter_at(clean) != 0)
            | (ere_should_report(real, hit) != 'b')
            | (ere_should_report(real, clean) != 0)
            | (ere_should_report(real, marked) != 0);
    const char *old = getenv("ZCL_LINT_PRODUCTION_SCAN");
    char saved[16];
    int had = 0;
    if (old) {
        if (ovf(snprintf(saved, sizeof saved, "%s", old), sizeof saved)) {
            regfree(&re);
            return 2;
        }
        had = 1;
    }
    if (setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1) != 0)
        bad = 1;
    bool r1 = (ere_should_report(excl, hit) != 0);
    bool r2 = (ere_should_report(real, hit) != 'b');
    bool r3 = !lint_path_is_excluded(excl);
    bool r4 = lint_path_is_excluded(real);
    bad |= r1;
    bad |= r2;
    bad |= r3;
    bad |= r4;
    if (had)
        (void)setenv("ZCL_LINT_PRODUCTION_SCAN", saved, 1);
    else
        (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    bad |= lint_path_is_excluded(excl);
    regfree(&re);
    return st_ok(bad, "check_posix_ere_only selftest: OK\n");
}

static int sql_glob(const char *s, const char *p)
{
    if (*p == '\0')
        return *s == '\0';
    if (*p == '*') {
        while (*p == '*')
            p++;
        if (*p == '\0')
            return 1;
        for (; *s; s++) {
            if (sql_glob(s, p))
                return 1;
        }
        return sql_glob(s, p);
    }
    if (*s != '\0' && *s == *p)
        return sql_glob(s + 1, p + 1);
    return 0;
}

static int wh_slashes(const char *s)
{
    int n = 0;
    for (; *s; s++)
        if (*s == '/')
            n++;
    return n;
}

static int wh_is_wire(const char *path)
{
    if (sql_glob(path, "engine/modules/sim/src/simnet_wire*.c")
        && wh_slashes(path) == 4)
        return 1;
    if (sql_glob(path, "tools/sim/*wire*.c") && wh_slashes(path) == 2)
        return 1;
    if (sql_glob(path, "tools/sim/*wire*.h") && wh_slashes(path) == 2)
        return 1;
    return 0;
}

static int wh_comp(regex_t *re)
{
    return reg_fail(re, regcomp(re,
        "(^|[^[:alnum:]_])(recv|send|socket|connect|bind|getaddrinfo)"
        "[[:space:]]*\\(", REG_EXTENDED));
}

enum { WH_OK = 0, WH_HOLLOW = 1, WH_HITS = 2 };

static int wh_verdict(int nfiles, int hits)
{
    if (nfiles == 0)
        return WH_HOLLOW;
    if (hits > 0)
        return WH_HITS;
    return WH_OK;
}

static int wh_report(int v, int nfiles)
{
    if (v == WH_HOLLOW) {
        fputs("FAIL: check_wire_harness_security_gate found no simnet_wire "
              "source files — gate is hollow\n", stdout);
        return 1;
    }
    if (v == WH_HITS) {
        fputs("FAIL: real-network call found in the simnet_wire in-memory harness\n",
              stdout);
        fputs("  simnet_wire is pure in-memory transport by design (deterministic,\n",
              stdout);
        fputs("  no wall-clock, no real sockets). If this is a legitimate need,\n",
              stdout);
        fputs("  it does not belong in engine/modules/sim/src/simnet_wire*.c or "
              "tools/sim/*wire*.\n", stdout);
        return 1;
    }
    printf("OK: check_wire_harness_security_gate — no "
           "recv/send/socket/connect/bind/getaddrinfo in %d wire harness file(s)\n",
           nfiles);
    return 0;
}

struct wh_acc { regex_t *re; int nfiles; int hits; };

static int on_wh(const char *path, void *ctx)
{
    struct wh_acc *a = ctx;
    if (!wh_is_wire(path))
        return 0;
    a->nfiles++;
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
        if (fprintf(stdout, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        a->hits++;
    }
    return fin(f, line, path, rc);
}

int check_wire_harness_security_gate_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    regex_t re;
    int cr = wh_comp(&re);
    if (cr)
        return cr;
    struct wh_acc a = { .re = &re, .nfiles = 0, .hits = 0 };
    int rc = each_zpath(k_ls_all, on_wh, &a);
    if (rc == 0)
        rc = wh_report(wh_verdict(a.nfiles, a.hits), a.nfiles);
    regfree(&re);
    return rc;
}

int check_wire_harness_security_gate_selftest(void)
{
    regex_t re;
    int cr = wh_comp(&re);
    if (cr)
        return cr;
    const char *t = "check_wire_harness_security_gate";
    int bad = want(t, &re, "simnet_wire_peer_send_ping(", 0)
            | want(t, &re, "drain_nut_send(", 0)
            | want(t, &re, "send(", 1)
            | want(t, &re, "    recv (fd, buf, n, 0);", 1)
            | want(t, &re, "xsend(", 0)
            | want(t, &re, "reconnect(", 0);
    regfree(&re);
    bad |= !wh_is_wire("engine/modules/sim/src/simnet_wire.c");
    bad |= !wh_is_wire("engine/modules/sim/src/simnet_wire_peer.c");
    bad |= !wh_is_wire("tools/sim/wire_sweep.c");
    bad |= !wh_is_wire("tools/sim/foo_wire.h");
    bad |= wh_is_wire("engine/modules/sim/src/other.c");
    bad |= wh_is_wire("engine/modules/sim/src/simnet_wire_x/y.c");
    bad |= wh_is_wire("tools/sim/nested/wire.c");
    bad |= wh_verdict(0, 0) != WH_HOLLOW;
    bad |= wh_verdict(3, 0) != WH_OK;
    bad |= wh_verdict(3, 1) != WH_HITS;
    return st_ok(bad, "check_wire_harness_security_gate selftest: OK\n");
}

static const char k_tdp_net[] =
    "zcl_service_kernel_start_all(&svc->network_kernel)";
static const char k_tdp_front[] =
    "zcl_service_kernel_start_all(&svc->frontend_kernel)";
static const char k_tdp_dial[] = "atomic_store(&g_tor_dial_ready, true)";
static const char k_tdp_pub[] = "tor_log_has_descriptor_publication\\(";
static const char k_tdp_dial_fn[] = "tor_integration_is_dial_ready";
static const char k_tdp_ready[] = "tor_integration_is_ready";

static int tdp_first_line(const char *path, const char *lit, const regex_t *re)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char *line = NULL;
    size_t cap = 0;
    int lineno = 0, found = -1;
    while (getline(&line, &cap, f) >= 0) {
        lineno++;
        int hit = 0;
        if (lit)
            hit = strstr(line, lit) != NULL;
        else if (re)
            hit = regexec(re, line, 0, NULL, 0) == 0;
        if (hit) {
            found = lineno;
            break;
        }
    }
    free(line);
    (void)fclose(f);
    return found;
}

static int tdp_before(int a, int b)
{
    return a >= 0 && b >= 0 && a < b;
}

static int tdp_has(const char *path, const char *lit)
{
    return tdp_first_line(path, lit, NULL) >= 0;
}

struct tdp_job {
    const char *boot;
    const char *tor;
    const char *stream;
    const char *connman;
    const char *watchdog;
    int progress;
    int step5_seen;
    int network_line;
    int frontend_line;
    int dial_ready_line;
    int publication_line;
    const char *err;
};

static int tdp_run_job(struct tdp_job *j)
{
    j->progress = 0;
    j->step5_seen = 0;
    j->err = NULL;
    j->network_line = -1;
    j->frontend_line = -1;
    j->dial_ready_line = -1;
    j->publication_line = -1;

    j->progress++;
    j->network_line = tdp_first_line(j->boot, k_tdp_net, NULL);
    j->frontend_line = tdp_first_line(j->boot, k_tdp_front, NULL);
    if (j->network_line < 0 || j->frontend_line < 0) {
        j->err = "could not resolve network/frontend boot order";
        return 1;
    }

    j->progress++;
    if (!tdp_before(j->network_line, j->frontend_line)) {
        j->err = "connman must start before the frontend Tor service";
        return 1;
    }

    regex_t pub;
    int cr = reg_fail(&pub, regcomp(&pub, k_tdp_pub, REG_EXTENDED));
    if (cr)
        return cr;
    j->progress++;
    j->dial_ready_line = tdp_first_line(j->tor, k_tdp_dial, NULL);
    j->publication_line = tdp_first_line(j->tor, NULL, &pub);
    regfree(&pub);
    if (j->dial_ready_line < 0 || j->publication_line < 0) {
        j->err = "could not resolve Tor dial/publication order";
        return 1;
    }

    j->progress++;
    if (!tdp_before(j->dial_ready_line, j->publication_line)) {
        j->err = "outbound dial readiness must precede descriptor publication";
        return 1;
    }

    j->progress++;
    j->step5_seen++;
    if (!tdp_has(j->stream, k_tdp_dial_fn)) {
        j->err = "raw onion stream still waits for full inbound readiness";
        return 1;
    }

    j->progress++;
    if (!tdp_has(j->connman, k_tdp_dial_fn)) {
        j->err = "onion seed discovery still waits for full inbound readiness";
        return 1;
    }

    j->progress++;
    if (tdp_has(j->stream, k_tdp_ready) || tdp_has(j->connman, k_tdp_ready)) {
        j->err = "an outbound onion path is still gated on descriptor publication";
        return 1;
    }

    j->progress++;
    if (!tdp_has(j->watchdog, k_tdp_ready)) {
        j->err = "systemd READY no longer waits for descriptor publication";
        return 1;
    }
    return 0;
}

int check_tor_dial_prewarm_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct tdp_job j = {
        .boot = "engine/composition/src/boot_services.c",
        .tor = "core/modules/net/src/tor_integration.c",
        .stream = "core/modules/net/src/onion_stream.c",
        .connman = "core/modules/net/src/connman.c",
        .watchdog = "engine/composition/src/boot_sd_watchdog.c",
    };
    int rc = tdp_run_job(&j);
    if (rc == 1) {
        if (fprintf(stderr, "check_tor_dial_prewarm: FAIL: %s\n",
                    j.err ? j.err : "unknown") < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (rc)
        return rc;
    if (printf("check_tor_dial_prewarm: PASS network_start=%d tor_start=%d "
               "dial_ready=%d descriptor_publication=%d\n",
               j.network_line, j.frontend_line, j.dial_ready_line,
               j.publication_line) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int tdp_st_want(int got, int w, const char *tag)
{
    if (got != w) {
        fprintf(stderr, "check_tor_dial_prewarm selftest: %s want %d got %d\n",
                tag, w, got);
        return 1;
    }
    return 0;
}

struct tdp_paths {
    const char *tmp;
    char two[4096], boot[4096], tor[4096], stream[4096], connman[4096],
        watchdog[4096];
};

static int tdp_st_paths_init(struct tdp_paths *p, const char *tmp)
{
    p->tmp = tmp;
    if (ovf(snprintf(p->two, sizeof p->two, "%s/two.c", tmp), sizeof p->two)
        || ovf(snprintf(p->boot, sizeof p->boot, "%s/boot.c", tmp),
               sizeof p->boot)
        || ovf(snprintf(p->tor, sizeof p->tor, "%s/tor.c", tmp), sizeof p->tor)
        || ovf(snprintf(p->stream, sizeof p->stream, "%s/stream.c", tmp),
               sizeof p->stream)
        || ovf(snprintf(p->connman, sizeof p->connman, "%s/connman.c", tmp),
               sizeof p->connman)
        || ovf(snprintf(p->watchdog, sizeof p->watchdog, "%s/watchdog.c", tmp),
               sizeof p->watchdog))
        return 2;
    return 0;
}

static int tdp_st_write_baseline(const struct tdp_paths *p)
{
    if (csr_write(p->two, "alpha\nbravo\n")
        || csr_write(p->boot,
                     "zcl_service_kernel_start_all(&svc->network_kernel)\n"
                     "zcl_service_kernel_start_all(&svc->frontend_kernel)\n")
        || csr_write(p->tor, "atomic_store(&g_tor_dial_ready, true)\n"
                          "tor_log_has_descriptor_publication(\n")
        || csr_write(p->stream, "tor_integration_is_dial_ready\n")
        || csr_write(p->connman, "tor_integration_is_dial_ready\n")
        || csr_write(p->watchdog, "tor_integration_is_ready\n"))
        return 2;
    return 0;
}

/* Each probe below returns -1 to signal a hard (fixture-write) failure that
 * must abort the selftest, or an accumulated 0/1 "bad" flag otherwise — the
 * same two outcomes the original inline selftest body produced at each
 * step, now named for the scenario each one drives.
 */

static int tdp_st_probe_literal_scan(struct tdp_job *j, struct tdp_paths *p)
{
    (void)j;
    int bad = 0;
    bad |= tdp_st_want(tdp_first_line(p->two, "alpha", NULL), 1, "lit-line1");
    bad |= tdp_st_want(tdp_first_line(p->two, "bravo", NULL), 2, "lit-line2");
    bad |= tdp_st_want(tdp_first_line(p->two, "missing", NULL), -1, "lit-miss");
    bad |= tdp_st_want(tdp_first_line(p->tmp, "alpha", NULL), -1, "unopenable");
    regex_t ere;
    int cr = reg_fail(&ere, regcomp(&ere, "bravo", REG_EXTENDED));
    if (cr)
        return -1;
    bad |= tdp_st_want(tdp_first_line(p->two, NULL, &ere), 2, "ere-line2");
    regfree(&ere);
    return bad;
}

static int tdp_st_probe_order_pure(struct tdp_job *j, struct tdp_paths *p)
{
    (void)j;
    (void)p;
    int bad = 0;
    bad |= tdp_st_want(tdp_before(1, 2), 1, "order-pass");
    bad |= tdp_st_want(tdp_before(2, 1), 0, "order-fail");
    bad |= tdp_st_want(tdp_before(-1, 2), 0, "order-unresolved");
    bad |= tdp_st_want(tdp_before(3, 3), 0, "order-equal");
    return bad;
}

static int tdp_st_probe_full_pass(struct tdp_job *j, struct tdp_paths *p)
{
    (void)p;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 0, "full-pass");
    bad |= tdp_st_want(j->progress, 8, "full-progress");
    bad |= tdp_st_want(j->network_line, 1, "net-line");
    bad |= tdp_st_want(j->frontend_line, 2, "front-line");
    bad |= tdp_st_want(j->dial_ready_line, 1, "dial-line");
    bad |= tdp_st_want(j->publication_line, 2, "pub-line");
    return bad;
}

static int tdp_st_probe_boot_order_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->boot,
                  "zcl_service_kernel_start_all(&svc->frontend_kernel)\n"
                  "zcl_service_kernel_start_all(&svc->network_kernel)\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "boot-order-fail");
    bad |= tdp_st_want(j->progress, 2, "boot-order-progress");
    bad |= !j->err || strcmp(j->err,
            "connman must start before the frontend Tor service") != 0;
    return bad;
}

static int tdp_st_probe_step1_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->boot, "no markers\n")
        || csr_write(p->stream, "no dial fn\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "step1-fail");
    bad |= tdp_st_want(j->progress, 1, "step1-progress");
    bad |= tdp_st_want(j->step5_seen, 0, "die-on-first-skips-step5");
    bad |= !j->err || strcmp(j->err,
            "could not resolve network/frontend boot order") != 0;
    return bad;
}

static int tdp_st_probe_dial_order_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->boot,
                  "zcl_service_kernel_start_all(&svc->network_kernel)\n"
                  "zcl_service_kernel_start_all(&svc->frontend_kernel)\n")
        || csr_write(p->tor, "tor_log_has_descriptor_publication(\n"
                          "atomic_store(&g_tor_dial_ready, true)\n")
        || csr_write(p->stream, "tor_integration_is_dial_ready\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "dial-order-fail");
    bad |= tdp_st_want(j->progress, 4, "dial-order-progress");
    bad |= !j->err || strcmp(j->err,
            "outbound dial readiness must precede descriptor publication") != 0;
    return bad;
}

static int tdp_st_probe_step5_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->tor, "atomic_store(&g_tor_dial_ready, true)\n"
                       "tor_log_has_descriptor_publication(\n")
        || csr_write(p->stream, "nope\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "step5-fail");
    bad |= tdp_st_want(tdp_has(p->stream, k_tdp_dial_fn), 0, "step5-has-fail");
    bad |= !j->err || strcmp(j->err,
            "raw onion stream still waits for full inbound readiness") != 0;
    return bad;
}

static int tdp_st_probe_step6_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->stream, "tor_integration_is_dial_ready\n")
        || csr_write(p->connman, "nope\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "step6-fail");
    bad |= tdp_st_want(tdp_has(p->connman, k_tdp_dial_fn), 0, "step6-has-fail");
    return bad;
}

static int tdp_st_probe_step7_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->connman, "tor_integration_is_dial_ready\n")
        || csr_write(p->stream,
                     "tor_integration_is_dial_ready\ntor_integration_is_ready\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "step7-fail");
    bad |= tdp_st_want(tdp_has(p->stream, k_tdp_ready)
                      || tdp_has(p->connman, k_tdp_ready), 1, "step7-has-fail");
    return bad;
}

static int tdp_st_probe_step8_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->stream, "tor_integration_is_dial_ready\n")
        || csr_write(p->watchdog, "nope\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "step8-fail");
    bad |= tdp_st_want(tdp_has(p->watchdog, k_tdp_ready), 0, "step8-has-fail");
    return bad;
}

static int tdp_st_probe_final_has_pass(struct tdp_job *j, struct tdp_paths *p)
{
    (void)j;
    int bad = 0;
    bad |= tdp_st_want(tdp_has(p->stream, k_tdp_dial_fn), 1, "step5-has-pass");
    if (csr_write(p->connman, "tor_integration_is_dial_ready\n")
        || csr_write(p->watchdog, "tor_integration_is_ready\n"))
        return -1;
    bad |= tdp_st_want(tdp_has(p->connman, k_tdp_dial_fn), 1, "step6-has-pass");
    bad |= tdp_st_want(tdp_has(p->stream, k_tdp_ready)
                      || tdp_has(p->connman, k_tdp_ready), 0, "step7-has-pass");
    bad |= tdp_st_want(tdp_has(p->watchdog, k_tdp_ready), 1, "step8-has-pass");
    return bad;
}

typedef int (*tdp_st_probe_fn)(struct tdp_job *j, struct tdp_paths *p);

static const tdp_st_probe_fn k_tdp_st_probes[] = {
    tdp_st_probe_literal_scan,
    tdp_st_probe_order_pure,
    tdp_st_probe_full_pass,
    tdp_st_probe_boot_order_fail,
    tdp_st_probe_step1_fail,
    tdp_st_probe_dial_order_fail,
    tdp_st_probe_step5_fail,
    tdp_st_probe_step6_fail,
    tdp_st_probe_step7_fail,
    tdp_st_probe_step8_fail,
    tdp_st_probe_final_has_pass,
};

int check_tor_dial_prewarm_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-tdp-XXXXXX", td), sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);

    struct tdp_paths p;
    int rc0 = tdp_st_paths_init(&p, tmp);
    if (!rc0)
        rc0 = tdp_st_write_baseline(&p);
    if (rc0) {
        (void)rap_rm_rf(tmp);
        return rc0;
    }

    struct tdp_job j = {
        .boot = p.boot, .tor = p.tor, .stream = p.stream,
        .connman = p.connman, .watchdog = p.watchdog,
    };

    int bad = 0;
    size_t n = sizeof k_tdp_st_probes / sizeof k_tdp_st_probes[0];
    for (size_t i = 0; i < n; i++) {
        int r = k_tdp_st_probes[i](&j, &p);
        if (r < 0) {
            (void)rap_rm_rf(tmp);
            return 2;
        }
        bad |= r;
    }

    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_tor_dial_prewarm selftest: OK\n");
}
