/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-zclassicd-reach-allowlist
 * Single-gate family file. Placement ruling (2026-09-06, Linux side): both
 * small-pattern families are claimed by lintc26 (gate_ratchet_ports.c) and
 * lintc28 (gate_pattern_small.c), so new ports land in their own files; the
 * older in-file routing comments that would have folded this gate into an
 * existing family are overridden by that ruling.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

/* ── check-zclassicd-reach-allowlist ─────────────────────────────────────
 * Byte-parity C23 port of the shell RATCHET gate
 * tools/lint/gate_zclassicd_reach_allowlist.sh (at c2f48bda2): the set of
 * non-test source files that reach an external zclassicd is FROZEN in the
 * inline allowlist below — a reaching file not on the list fails the gate,
 * while a listed file that stopped reaching is tolerated and named as a
 * prunable note (superset-allowed, never fatal). Scan: recursive find over
 * core engine contexts cognition platform for regular .c/.h/.def files
 * whose content matches the reach ERE, minus the exclusion ERE (test/soak
 * harness paths and the agent-impact registry, which stores path strings,
 * not runtime code). The shared baseline helper does NOT apply:
 * lint_base_load is exact-pin (grew/shrank/stale all fail) and
 * lint_base_load_set loads a FILE with '#' comments — this gate's contract
 * is an inline static table with stale-as-note and locale `sort -u`/`comm`
 * ordering, matching neither. */

static const char *const k_zra_allow[] = {
    "engine/conditions/src/tip_stall_oracle_rebuild.c",
    "engine/controllers/src/diagnostics_registry.c",
    "engine/controllers/src/probe_controller.c",
    "engine/controllers/src/repair_controller_rebuild.c",
    "engine/services/include/services/oracle_policy.h",
    "engine/services/include/services/quorum_oracle_service.h",
    "engine/services/include/services/zclassicd_oracle_service.h",
    "engine/services/src/quorum_oracle_service.c",
    "engine/services/src/snapshot_verify.c",
    "engine/services/src/zclassicd_oracle_service.c",
    "engine/composition/include/config/boot_internal.h",
    "engine/composition/src/boot_runtime_sync_services.c",
    "engine/composition/src/boot_services.c",
    "core/modules/net/src/fast_sync.c",
    "engine/modules/rpc/include/rpc/legacy_chain_oracle.h",
    "engine/modules/rpc/src/legacy_chain_oracle.c",
    "engine/entry/main.c",
};
enum { ZRA_N_ALLOW = (int)(sizeof k_zra_allow / sizeof k_zra_allow[0]) };

static const char *const k_zra_tops[] = {
    "core", "engine", "contexts", "cognition", "platform"
};

struct zra_list { char **v; size_t n, cap; };
struct zra_acc { regex_t *hit, *excl; struct zra_list cur; };

static int zra_comp(regex_t *hit, regex_t *excl)
{
    int cr = reg_fail(hit, regcomp(hit,
        "legacy_chain_rpc_|legacy_chain_oracle|zclassicd_oracle|"
        "127\\.0\\.0\\.1:8232|:8034|:8232|getblock-from-mirror",
        REG_EXTENDED));
    if (cr)
        return cr;
    cr = reg_fail(excl, regcomp(excl,
        "(^|/)tests/harness/include/test/|(^|/)tools/soak/|_test\\.c$|"
        "(^|/)tools/crash_recovery_test\\.c$|"
        "(^|/)cognition/controllers/include/controllers/"
        "agent_impact_rules\\.def$", REG_EXTENDED));
    if (cr)
        regfree(hit);
    return cr;
}

static int zra_push(struct zra_list *l, const char *path)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 32;
        char **nv = realloc(l->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        l->v = nv;
        l->cap = nc;
    }
    char *copy = strdup(path);
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    l->v[l->n++] = copy;
    return 0;
}

static void zra_free(struct zra_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
}

static int zra_cmp(const void *a, const void *b)
{
    return strcoll(*(const char *const *)a, *(const char *const *)b);
}

/* sort -u under the ambient locale (the caller setlocale()s first):
 * collation-equal lines collapse the way sort -u drops them. */
static void zra_sort_uniq(struct zra_list *l)
{
    qsort(l->v, l->n, sizeof l->v[0], zra_cmp);
    size_t w = 0;
    for (size_t i = 0; i < l->n; i++) {
        if (w > 0 && strcoll(l->v[w - 1], l->v[i]) == 0) {
            free(l->v[i]);
            continue;
        }
        l->v[w++] = l->v[i];
    }
    l->n = w;
}

/* grep -El: 1 when any line matches. Scan errors are silent, exactly as
 * under the shell gate's `find ... -exec grep -El ... + 2>/dev/null`. */
static int zra_reaches(const char *full, const regex_t *hit)
{
    FILE *f = fopen(full, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0)
        found = regexec(hit, line, 0, NULL, 0) == 0;
    free(line);
    (void)fclose(f);
    return found;
}

static int zra_suffix(const char *name)
{
    size_t n = strlen(name);
    if (n >= 2 && name[n - 2] == '.'
        && (name[n - 1] == 'c' || name[n - 1] == 'h'))
        return 1;
    return n >= 4 && memcmp(name + n - 4, ".def", 4) == 0;
}

/* find <top> -type f \( -name '*.c' -o -name '*.h' -o -name '*.def' \):
 * lstat (symlinks are never followed), silent on unreadable dirs/files. */
static int zra_walk(const char *dir, const char *rel, struct zra_acc *a)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return 0;
    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        const char *name = names[i]->d_name;
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char full[4096], sub[4096];
            struct stat st;
            if (ovf(snprintf(full, sizeof full, "%s/%s", dir, name),
                    sizeof full)
                || ovf(snprintf(sub, sizeof sub, "%s/%s", rel, name),
                       sizeof sub))
                rc = 2;
            else if (lstat(full, &st) == 0 && S_ISDIR(st.st_mode))
                rc = zra_walk(full, sub, a);
            else if (lstat(full, &st) == 0 && S_ISREG(st.st_mode)
                     && zra_suffix(name)
                     && regexec(a->excl, sub, 0, NULL, 0) != 0
                     && zra_reaches(full, a->hit))
                rc = zra_push(&a->cur, sub);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int zra_collect(const char *root, struct zra_acc *a)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_zra_tops / sizeof k_zra_tops[0];
         i++) {
        char dir[4096];
        int k = strcmp(root, ".") == 0
            ? snprintf(dir, sizeof dir, "%s", k_zra_tops[i])
            : snprintf(dir, sizeof dir, "%s/%s", root, k_zra_tops[i]);
        if (ovf(k, sizeof dir))
            return 2;
        rc = zra_walk(dir, k_zra_tops[i], a);
    }
    return rc;
}

/* comm membership against the sorted allowlist, strcoll-ordered like the
 * shell's `sort -u` + `comm` pair under the ambient locale. */
static int zra_rank(const char *const *al, const char *path)
{
    int lo = 0, hi = ZRA_N_ALLOW - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        int c = strcoll(path, al[mid]);
        if (c == 0)
            return mid;
        if (c < 0)
            hi = mid - 1;
        else
            lo = mid + 1;
    }
    return -1;
}

/* The fail path's per-file evidence: `  + <path>` then the shell's
 * `grep -nE "$PAT" <path> | sed 's/^/      /'` — lineno:line, 6-space
 * indent, to stderr. A file that vanishes mid-report prints no context
 * (grep's stderr was silenced and it would exit 2 having printed nothing
 * useful; the gate's FAIL line above already names the file). */
static int zra_show_reach(const char *root, const char *path,
                          const regex_t *hit, FILE *err)
{
    if (fprintf(err, "  + %s\n", path) < 0)
        return die("z23-lint: write failed\n", "");
    char full[4096];
    int k = strcmp(root, ".") == 0
        ? snprintf(full, sizeof full, "%s", path)
        : snprintf(full, sizeof full, "%s/%s", root, path);
    if (ovf(k, sizeof full))
        return 2;
    FILE *f = fopen(full, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int lineno = 0, rc = 0;
    while ((len = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(hit, line, 0, NULL, 0) != 0)
            continue;
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (fprintf(err, "      %d:%s\n", lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    free(line);
    (void)fclose(f);
    return rc;
}

static int zra_fail_new(const char *root, const struct zra_list *cur,
                        const char *const *al, const regex_t *hit, FILE *err)
{
    if (fputs("FAIL: gate_zclassicd_reach_allowlist — new zclassicd "
              "reach(es) outside the frozen allowlist:\n", err) < 0)
        return die("z23-lint: write failed\n", "");
    for (size_t i = 0; i < cur->n; i++) {
        if (zra_rank(al, cur->v[i]) >= 0)
            continue;
        int rc = zra_show_reach(root, cur->v[i], hit, err);
        if (rc)
            return rc;
    }
    if (fputs("\nThe node must stand alone — runtime/boot zclassicd "
              "dependence may not grow.\n"
              "If this reach is genuinely required, add the file to "
              "ALLOWLIST in\n"
              "tools/lint/gate_zclassicd_reach_allowlist.sh AND justify it "
              "in the commit.\n", err) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int zra_pass(const int *seen, const char *const *al, size_t count,
                    FILE *out, FILE *err)
{
    int stale = 0;
    for (int i = 0; i < ZRA_N_ALLOW; i++)
        stale += !seen[i];
    if (stale > 0) {
        if (fputs("note: gate_zclassicd_reach_allowlist — allowlist entries "
                  "that no longer reach (prunable):\n", err) < 0)
            return die("z23-lint: write failed\n", "");
        for (int i = 0; i < ZRA_N_ALLOW; i++)
            if (!seen[i] && fprintf(err, "  - %s\n", al[i]) < 0)
                return die("z23-lint: write failed\n", "");
    }
    if (fprintf(out, "gate_zclassicd_reach_allowlist: OK (%zu non-test "
                "source files reach zclassicd; none new)\n", count) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int zra_report(const char *root, const struct zra_list *cur,
                      const regex_t *hit, FILE *out, FILE *err)
{
    const char *al[ZRA_N_ALLOW];
    int seen[ZRA_N_ALLOW];
    for (int i = 0; i < ZRA_N_ALLOW; i++) {
        al[i] = k_zra_allow[i];
        seen[i] = 0;
    }
    qsort(al, ZRA_N_ALLOW, sizeof al[0], zra_cmp);
    size_t n_new = 0;
    for (size_t i = 0; i < cur->n; i++) {
        int idx = zra_rank(al, cur->v[i]);
        if (idx >= 0)
            seen[idx] = 1;
        else
            n_new++;
    }
    if (n_new > 0)
        return zra_fail_new(root, cur, al, hit, err);
    return zra_pass(seen, al, cur->n, out, err);
}

static int zra_check(const char *root, FILE *out, FILE *err)
{
    regex_t hit, excl;
    int rc = zra_comp(&hit, &excl);
    if (rc)
        return rc;
    struct zra_acc a = { .hit = &hit, .excl = &excl,
                         .cur = { NULL, 0, 0 } };
    rc = zra_collect(root, &a);
    if (rc == 0) {
        (void)setlocale(LC_COLLATE, "");
        zra_sort_uniq(&a.cur);
        rc = zra_report(root, &a.cur, &hit, out, err);
    }
    zra_free(&a.cur);
    drop2(&hit, &excl);
    return rc;
}

int check_zclassicd_reach_allowlist_run(int argc, char **argv)
{
    char cwd[4096];
    const char *root = NULL;
    if (argc > 0 && argv[0][0])
        root = argv[0];
    else if (env_or("GATE_ROOT", "")[0])
        root = getenv("GATE_ROOT");
    else {
        if (!getcwd(cwd, sizeof cwd))
            return die("z23-lint: getcwd failed\n", "");
        root = cwd;
    }
    for (size_t i = 0; i < sizeof k_zra_tops / sizeof k_zra_tops[0]; i++) {
        char d[4096];
        struct stat st;
        if (ovf(snprintf(d, sizeof d, "%s/%s", root, k_zra_tops[i]),
                sizeof d))
            return 2;
        if (stat(d, &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "gate_zclassicd_reach_allowlist: '%s' is not a "
                    "zclassic23 checkout\n", root);
            return 2;
        }
    }
    /* cd "$ROOT" || exit 2 — no message on chdir failure, as in the shell. */
    if (chdir(root) != 0)
        return 2;
    return zra_check(".", stdout, stderr);
}

/* ── selftest (the shell gate's 3-case --selftest, verbatim messages) ──── */

static int zra_st_case(const char *root, int want_ok, const char *needle)
{
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    int rc = zra_check(root, out, err);
    char bo[8192], be[8192], both[16384];
    int src = csr_slurp(out, bo, sizeof bo) | csr_slurp(err, be, sizeof be)
        | ovf(snprintf(both, sizeof both, "%s%s", bo, be), sizeof both);
    fclose(out);
    fclose(err);
    if (src)
        return 1;
    int ok = want_ok ? rc == 0 : rc != 0;
    if (ok && needle && !strstr(both, needle))
        ok = 0;
    return ok ? 0 : 1;
}

static int zra_st_tree(const char *root)
{
    static const char *const dirs[] = {
        "core", "contexts", "platform",
        "engine/controllers/include/controllers",
        "engine/services/src",
        "cognition/controllers/include/controllers",
    };
    char p[4096];
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++)
        if (ovf(snprintf(p, sizeof p, "%s/%s", root, dirs[i]), sizeof p)
            || csr_mkdirs(p))
            return 1;
    return 0;
}

static int zra_st_fail(const char *root, const char *msg)
{
    fputs(msg, stderr);
    (void)rap_rm_rf(root);
    return 2;
}

int check_zclassicd_reach_allowlist_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-zra-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    char p[4096];
    int bad = zra_st_tree(root);
    const char *reach = "static const char *probe = \"zclassicd_oracle\";\n";
    if (!bad
        && (ovf(snprintf(p, sizeof p, "%s/cognition/controllers/include/"
                         "controllers/agent_impact_rules.def", root), sizeof p)
            || csr_write(p, "AGENT_IMPACT_RULE(\"engine/services/src/"
                         "zclassicd_oracle_service.c\", \"rpc\")\n")))
        bad = 1;
    if (bad) {
        (void)rap_rm_rf(root);
        return 2;
    }
    /* the exact metadata registry is excluded — the tmp tree passes */
    if (zra_st_case(root, 1, NULL))
        return zra_st_fail(root, "gate_zclassicd_reach_allowlist: SELFTEST "
            "FAILED — exact metadata registry was treated as runtime code\n");
    /* a runtime reach outside the allowlist fails */
    if (ovf(snprintf(p, sizeof p, "%s/engine/services/src/runtime_probe.c",
                     root), sizeof p)
        || csr_write(p, reach))
        return zra_st_fail(root, "");
    if (zra_st_case(root, 0, "  + engine/services/src/runtime_probe.c\n"))
        return zra_st_fail(root, "gate_zclassicd_reach_allowlist: SELFTEST "
            "FAILED — runtime reach was accepted\n");
    if (unlink(p) != 0)
        return zra_st_fail(root, "");
    /* a similarly named metadata file does NOT escape — exact-path anchor */
    if (ovf(snprintf(p, sizeof p, "%s/cognition/controllers/include/"
                     "controllers/agent_impact_rules_extra.def", root),
            sizeof p)
        || csr_write(p, reach))
        return zra_st_fail(root, "");
    if (zra_st_case(root, 0, "  + cognition/controllers/include/controllers/"
                    "agent_impact_rules_extra.def\n"))
        return zra_st_fail(root, "gate_zclassicd_reach_allowlist: SELFTEST "
            "FAILED — similarly named metadata file escaped\n");
    (void)rap_rm_rf(root);
    fputs("gate_zclassicd_reach_allowlist: SELFTEST PASS (exact metadata "
          "excluded; runtime and near-name reaches fail)\n", stdout);
    return 0;
}
