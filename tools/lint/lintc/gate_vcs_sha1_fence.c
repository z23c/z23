/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-vcs-no-sha1 (port of
 * tools/scripts/check_vcs_no_sha1.sh, now a shim). HARD gate: ZVCS and
 * producer-source authority may not inherit Git/SHA-1. ZVCS and content.v2
 * use SHA3-256; the dev supersession identity uses a SHA-256 digest of
 * current source bytes. Git object ids may remain external GitHub
 * trace/publish metadata, never an input to these authority digests.
 *
 * Port notes (parity contract with the shell original):
 *  - grep -r walks a directory in readdir order; this port walks in
 *    scandir/alphasort order (the runtime's walk_src idiom). Violation
 *    output is byte-identical for any single-hit case and for the clean
 *    tree; an output with hits in MULTIPLE files can list them in a
 *    different order. Same class of documented non-parity as awk
 *    associative-array order in gate_pattern_small.c.
 *  - A file the walk opens but cannot read is UNPROVEN: exit 2, with the
 *    same "grep: <path>: <error>" + "grep failed with rc=2" stderr shape
 *    the original produced through grep. Never silently skipped.
 *  - The original's self-test injected a failing grep via PATH; this port
 *    has no subprocess, so the equivalent fail-closed proof is an
 *    unreadable scanned file (chmod 000), which must trip exit 2.
 *  - The shell cd'd to $ROOT before scanning; every path this gate uses is
 *    already $ROOT-prefixed, so the port scans without chdir. A missing
 *    $ROOT trips the same "cannot enter" FATAL the cd would have.
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
#include <unistd.h>
#include "lintc.h"

enum { VCS_PATH = 4096, VCS_LINE = 8192, VCS_HEADER = 1024, VCS_MKBUF = 8192 };

static int vcs_fatal(const char *msg, FILE *err)
{
    fprintf(err, "check_vcs_no_sha1: FATAL — %s\n", msg);
    return 2;
}

static int vcs_fatal_path(const char *prefix, const char *path, FILE *err)
{
    fprintf(err, "check_vcs_no_sha1: FATAL — %s%s\n", prefix, path);
    return 2;
}

/* grep's own rc>=2 report, mirrored: the failing entry's error line, then
 * the gate fatal naming the top-level scan argument. */
static int vcs_grep_fail(const char *entry, int e, const char *top, FILE *err)
{
    fprintf(err, "grep: %s: %s\n", entry, strerror(e));
    char msg[VCS_PATH + 64];
    if (ovf(snprintf(msg, sizeof msg, "grep failed with rc=2 scanning %s", top),
            sizeof msg))
        return 2;
    return vcs_fatal(msg, err);
}

static int vcs_scannable(const char *name)
{
    size_t n = strlen(name);
    if (strcmp(name, "Makefile") == 0)
        return 1;
    if (n >= 2 && name[n - 2] == '.'
        && (name[n - 1] == 'c' || name[n - 1] == 'h'))
        return 1;
    return n >= 3 && memcmp(name + n - 3, ".sh", 3) == 0;
}

static int vcs_grep_file(const char *path, const char *top, const regex_t *re,
                         FILE *out, FILE *err, int *hits, int show, int prefix)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return vcs_grep_fail(path, errno, top, err);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(re, line, 0, NULL, 0) != 0)
            continue;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        /* grep prefixes the operand path only when it recursed into a
         * directory; a lone file operand prints bare "line:text". */
        int w = show ? (prefix ? fprintf(out, "%s:%d:%s\n", path, lineno, line)
                               : fprintf(out, "%d:%s\n", lineno, line))
                     : 0;
        if (w < 0) {
            rc = 2;
            break;
        }
        (*hits)++;
    }
    if (rc == 0 && ferror(f))
        rc = vcs_grep_fail(path, EIO, top, err);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = vcs_fatal_path("read failed: ", path, err);
    return rc;
}

static int vcs_walk(const char *dir, const char *top, const regex_t *re,
                    FILE *out, FILE *err, int *hits, int show)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return errno == ENOENT ? 0 : vcs_grep_fail(dir, errno, top, err);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[VCS_PATH];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = vcs_fatal_path("path too long: ", dir, err);
            else if (lstat(path, &st) != 0)
                rc = vcs_grep_fail(path, errno, top, err);
            else if (S_ISDIR(st.st_mode))
                rc = vcs_walk(path, top, re, out, err, hits, show);
            else if (S_ISREG(st.st_mode) && vcs_scannable(name))
                rc = vcs_grep_file(path, top, re, out, err, hits, show, 1);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

/* grep_checked(): -rnEi with the include set over a file or directory.
 * show=0 mirrors grep -q: count only, print nothing. */
static int vcs_grep_checked(const char *path, const regex_t *re, FILE *out,
                            FILE *err, int *hits, int show)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return vcs_grep_fail(path, errno, path, err);
    if (S_ISDIR(st.st_mode))
        return vcs_walk(path, path, re, out, err, hits, show);
    return vcs_grep_file(path, path, re, out, err, hits, show, 0);
}

static int vcs_comp(regex_t *re, const char *pat, int icase)
{
    return reg_fail(re, regcomp(re, pat,
                                REG_EXTENDED | (icase ? REG_ICASE : 0)));
}

/* ── source-identity.sh git-call allowlist ────────────────────────────── */

static const char *const k_git_allow[] = {
    "git rev-parse --show-toplevel",
    "git rev-parse --git-path index",
    "git -C \"$prefix\" rev-parse --show-toplevel",
    "git -C \"$prefix\" rev-parse --git-path index",
    "git -C \"$repo\" config --null --list",
    "git -C \"$repo\" rev-parse --git-path info/exclude",
    "git -C \"$repo\" config --path --null --get core.excludesFile",
    "git ls-files -v -z",
    "git ls-files --others --exclude-standard -z --",
    "git ls-files --others --ignored --exclude-standard --directory -z --",
    "git diff --name-only --no-renames -z HEAD --",
    "git -C \"$prefix\" ls-files -v -z",
    "git -C \"$prefix\" ls-files --others --exclude-standard -z --",
    "git -C \"$prefix\" diff --name-only --no-renames -z HEAD --",
    "git -C \"$prefix\" ls-files --stage -z --",
    "git ls-files --stage -z --",
};

static int vcs_git_allowed(const char *code)
{
    for (size_t i = 0; i < sizeof k_git_allow / sizeof k_git_allow[0]; i++)
        if (strstr(code, k_git_allow[i]) != NULL)
            return 1;
    return 0;
}

/* sed 's/[[:space:]]*#.*$//' — cut at the first '#', trailing whitespace
 * ahead of it included. */
static void vcs_strip_comment(char *line)
{
    char *h = strchr(line, '#');
    if (!h)
        return;
    while (h > line && (h[-1] == ' ' || h[-1] == '\t'))
        h--;
    *h = '\0';
}

static int vcs_git_call_line(const char *code, int nr, FILE *out)
{
    int bad = 0;
    if (!vcs_git_allowed(code)) {
        fprintf(out, "FAIL: non-allowlisted Git command in source identity: "
                     "%d:%s\n", nr, code);
        bad = 1;
    }
    const char *first = strstr(code, "git ");
    if (first && strstr(first + 4, "git ") != NULL) {
        fprintf(out, "FAIL: multiple Git invocations on source-identity line: "
                     "%d:%s\n", nr, code);
        bad = 1;
    }
    return bad;
}

static int vcs_git_calls_allowed(const char *path, const regex_t *re,
                                 FILE *out, FILE *err)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return vcs_grep_fail(path, errno, path, err);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int nr = 0, bad = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        nr++;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        vcs_strip_comment(line);
        if (regexec(re, line, 0, NULL, 0) != 0)
            continue;
        if (vcs_git_call_line(line, nr, out))
            bad = 1;
    }
    if (ferror(f))
        rc = vcs_fatal_path("read failed: ", path, err);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = vcs_fatal_path("read failed: ", path, err);
    return rc ? rc : bad;
}

/* ── Makefile record lines ────────────────────────────────────────────── */

/* grep -E '^<name>[[:space:]]*:=' over the makefile, all matching lines
 * joined with '\n' the way a shell capture holds them. */
static int vcs_make_var(const char *mk, const char *name, char *outbuf,
                        size_t cap, FILE *err)
{
    char pat[128];
    if (ovf(snprintf(pat, sizeof pat, "^%s[[:space:]]*:=", name), sizeof pat))
        return 2;
    regex_t re;
    int cr = vcs_comp(&re, pat, 0);
    if (cr)
        return cr;
    FILE *f = fopen(mk, "r");
    if (!f) {
        regfree(&re);
        return vcs_fatal_path("read failed: ", mk, err);
    }
    char *line = NULL;
    size_t lcap = 0, used = 0;
    outbuf[0] = '\0';
    int rc = 0;
    while (getline(&line, &lcap, f) >= 0) {
        if (regexec(&re, line, 0, NULL, 0) != 0)
            continue;
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        int k = snprintf(outbuf + used, cap - used, "%s%s",
                         used ? "\n" : "", line);
        if (ovf(k, cap - used)) {
            rc = 2;
            break;
        }
        used += (size_t)k;
    }
    if (rc == 0 && ferror(f))
        rc = vcs_fatal_path("read failed: ", mk, err);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = vcs_fatal_path("read failed: ", mk, err);
    regfree(&re);
    return rc;
}

static int vcs_record_lines_ok(const char *mk, FILE *out, FILE *err)
{
    static char rec[VCS_MKBUF], src[VCS_MKBUF], cln[VCS_MKBUF], mut[VCS_MKBUF];
    int rc = vcs_make_var(mk, "BUILD_SOURCE_RECORD", rec, sizeof rec, err);
    if (rc == 0)
        rc = vcs_make_var(mk, "BUILD_SOURCE_ID", src, sizeof src, err);
    if (rc == 0)
        rc = vcs_make_var(mk, "BUILD_CLEAN", cln, sizeof cln, err);
    if (rc == 0)
        rc = vcs_make_var(mk, "BUILD_MUTATION", mut, sizeof mut, err);
    if (rc)
        return rc;
    if (rec[0] != '\0'
        && strstr(rec, "tools/dev/source-identity.sh capture-record") != NULL
        && strstr(rec, "git ") == NULL
        && strstr(src, "$(word 1,$(BUILD_SOURCE_RECORD))") != NULL
        && strstr(cln, "$(word 2,$(BUILD_SOURCE_RECORD))") != NULL
        && strstr(mut, "$(word 3,$(BUILD_SOURCE_RECORD))") != NULL)
        return 0;
    fprintf(out, "FAIL: build identity/clean/mutation state is not one "
                 "source-identity.v2 record: %s | %s | %s | %s\n",
            rec[0] ? rec : "missing", src[0] ? src : "missing",
            cln[0] ? cln : "missing", mut[0] ? mut : "missing");
    return 1;
}

/* ── identity_publications_verified() ─────────────────────────────────── */

struct ipv {
    regex_t re_rule, re_assign, re_identity, re_verified, re_pubtool,
            re_publish;
    int identity, publish, verified, delegated, bad;
    long verify_line, publish_line;
    char header[VCS_HEADER];
    FILE *out;
};

static void ipv_flush(struct ipv *s)
{
    if (s->identity && s->publish
        && (!s->verified || (!s->delegated && s->verify_line >= s->publish_line))) {
        fprintf(s->out, "FAIL: identity-bearing publication lacks in-rule "
                        "verification: %s\n", s->header);
        s->bad = 1;
    }
    s->identity = s->publish = s->verified = s->delegated = 0;
    s->verify_line = s->publish_line = 0;
}

static int ipv_compile(struct ipv *s, FILE *out)
{
    memset(s, 0, sizeof *s);
    s->out = out;
    int cr = vcs_comp(&s->re_rule, "^[^[:space:]#][^:]*:", 0);
    if (cr == 0)
        cr = vcs_comp(&s->re_assign, "^[^:]*:[[:space:]]*=", 0);
    if (cr == 0)
        cr = vcs_comp(&s->re_identity,
                      "BUILD_SOURCE_ID|ZCL_BUILD_SOURCE_ID|BUILD_IDENTITY_STAMP", 0);
    if (cr == 0)
        cr = vcs_comp(&s->re_verified,
                      "source-identity\\.sh[[:space:]]+verify-record"
                      "|BUILD_EPOCH_SESSION_TOOL\\)[[:space:]]+verify"
                      "|BUILD_EPOCH_PUBLISH_TOOL\\)", 0);
    if (cr == 0)
        cr = vcs_comp(&s->re_pubtool, "BUILD_EPOCH_PUBLISH_TOOL\\)", 0);
    if (cr == 0)
        cr = vcs_comp(&s->re_publish,
                      "publish_exact|BUILD_EPOCH_PUBLISH_TOOL\\)"
                      "|(^|[[:space:]])@?(mv|cp|install|ln)[[:space:]].*\\$+@"
                      "|-o[[:space:]]+[^[:space:]]*\\$+@", 0);
    return cr;
}

static void ipv_free(struct ipv *s)
{
    regfree(&s->re_rule);
    regfree(&s->re_assign);
    regfree(&s->re_identity);
    regfree(&s->re_verified);
    regfree(&s->re_pubtool);
    regfree(&s->re_publish);
}

static void ipv_line(struct ipv *s, const char *line, long nr)
{
    if (regexec(&s->re_rule, line, 0, NULL, 0) == 0
        && regexec(&s->re_assign, line, 0, NULL, 0) != 0) {
        ipv_flush(s);
        if (strlen(line) < sizeof s->header) {
            memcpy(s->header, line, strlen(line) + 1);
        } else {
            s->header[0] = '\0';
            s->bad = 1;
        }
    }
    if (regexec(&s->re_identity, line, 0, NULL, 0) == 0)
        s->identity = 1;
    if (regexec(&s->re_verified, line, 0, NULL, 0) == 0) {
        s->verified = 1;
        s->verify_line = nr;
        if (regexec(&s->re_pubtool, line, 0, NULL, 0) == 0)
            s->delegated = 1;
    }
    if (regexec(&s->re_publish, line, 0, NULL, 0) == 0) {
        s->publish = 1;
        s->publish_line = nr;
    }
}

static int ipv_rules_checked(const char *mk, FILE *out, FILE *err)
{
    struct ipv s;
    int cr = ipv_compile(&s, out);
    if (cr)
        return cr;
    FILE *f = fopen(mk, "r");
    if (!f) {
        ipv_free(&s);
        return vcs_fatal_path("read failed: ", mk, err);
    }
    char *line = NULL;
    size_t cap = 0;
    long nr = 0;
    int rc = 0;
    while (getline(&line, &cap, f) >= 0) {
        nr++;
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n')
            line[n - 1] = '\0';
        ipv_line(&s, line, nr);
    }
    ipv_flush(&s);
    if (ferror(f))
        rc = vcs_fatal_path("read failed: ", mk, err);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = vcs_fatal_path("read failed: ", mk, err);
    ipv_free(&s);
    return rc ? rc : s.bad;
}

/* grep -nF <needle> <path> | tail -1 | cut -d: -f1 — the LAST line number
 * holding the fixed string, 0 when absent. */
static int vcs_last_hit(const char *path, const char *needle, long *out,
                        FILE *err)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return vcs_fatal_path("read failed: ", path, err);
    char *line = NULL;
    size_t cap = 0;
    long nr = 0;
    *out = 0;
    int rc = 0;
    while (getline(&line, &cap, f) >= 0) {
        nr++;
        if (strstr(line, needle) != NULL)
            *out = nr;
    }
    if (ferror(f))
        rc = vcs_fatal_path("read failed: ", path, err);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = vcs_fatal_path("read failed: ", path, err);
    return rc;
}

static int vcs_delegation_checked(const char *publish_tool,
                                  const char *session_tool, FILE *out,
                                  FILE *err)
{
    long verify = 0, publish = 0, srcverify = 0;
    int rc = vcs_last_hit(publish_tool, "\"$SESSION_TOOL\" verify", &verify, err);
    if (rc == 0)
        rc = vcs_last_hit(publish_tool, "mv -f -- \"$TMP\" \"$ALIAS\"",
                          &publish, err);
    if (rc == 0)
        rc = vcs_last_hit(session_tool, "\"$VERIFY_TOOL\" verify-record",
                          &srcverify, err);
    if (rc)
        return rc;
    if (verify > 0 && publish > 0 && verify < publish && srcverify > 0)
        return 0;
    fputs("FAIL: delegated build-alias publication is not source-reverified "
          "before rename\n", out);
    return 1;
}

/* ── mutation_receipt_confined() ──────────────────────────────────────── */

static const char *const k_mut_exact[] = {
    "$(TEST_FAST_OBJ_DIR)/platform/modules/util/src/clientversion.o: TEST_FAST_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)",
    "$(TEST_REL_OBJ_DIR)/platform/modules/util/src/clientversion.o: TEST_REL_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)",
    "$(TEST_ASAN_OBJ_DIR)/platform/modules/util/src/clientversion.o: TEST_ASAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)",
    "$(DEV_ASAN_OBJ_DIR)/platform/modules/util/src/clientversion.o: DEV_ASAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)",
    "$(TEST_TSAN_OBJ_DIR)/platform/modules/util/src/clientversion.o: TEST_TSAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)",
    "$(DEV_TSAN_OBJ_DIR)/platform/modules/util/src/clientversion.o: DEV_TSAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)",
    "$(COV_BUILD_DIR)/platform/modules/util/src/clientversion.o: COV_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)",
    "$(DEV_OBJ_DIR)/platform/modules/util/src/clientversion.o: DEV_COMPILE_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)",
};

static const char k_mut_def[] =
    "DEV_SOURCE_RECEIPT_CPPFLAGS = -DZCL_BUILD_SOURCE_MUTATION=\\\"$(BUILD_MUTATION)\\\"";

/* Shell glob `*A*B*C`: the three literal parts present in order. */
static int vcs_glob3(const char *s, const char *a, const char *b,
                     const char *c)
{
    const char *p = strstr(s, a);
    if (!p)
        return 0;
    p = strstr(p + strlen(a), b);
    if (!p)
        return 0;
    return strstr(p + strlen(b), c) != NULL;
}

static int vcs_mut_line_ok(const char *code)
{
    if (strcmp(code, k_mut_def) == 0)
        return 2;
    for (size_t i = 0; i < sizeof k_mut_exact / sizeof k_mut_exact[0]; i++)
        if (strcmp(code, k_mut_exact[i]) == 0)
            return 1;
    if (vcs_glob3(code, "$(eval $(call BUILD_NODE_TOOL,test_zcl,",
                  "$(DEV_SOURCE_RECEIPT_CPPFLAGS)", "))"))
        return 1;
    return vcs_glob3(code, "$(eval $(call BUILD_NODE_TOOL,test_parallel_wpo,",
                     "$(DEV_SOURCE_RECEIPT_CPPFLAGS)", "))");
}

static int vcs_mutation_confined(const char *mk, FILE *out, FILE *err)
{
    regex_t re;
    int cr = vcs_comp(&re, "ZCL_BUILD_SOURCE_MUTATION|DEV_SOURCE_RECEIPT_CPPFLAGS", 0);
    if (cr)
        return cr;
    FILE *f = fopen(mk, "r");
    if (!f) {
        regfree(&re);
        return vcs_fatal_path("read failed: ", mk, err);
    }
    char *line = NULL;
    size_t cap = 0;
    int nr = 0, seen = 0, bad = 0, rc = 0;
    while (getline(&line, &cap, f) >= 0) {
        nr++;
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        if (regexec(&re, line, 0, NULL, 0) != 0)
            continue;
        int ok = vcs_mut_line_ok(line);
        if (ok == 2)
            seen++;
        else if (!ok) {
            fprintf(out, "FAIL: host-local mutation receipt escaped dev/test "
                         "identity TU: %d:%s\n", nr, line);
            bad = 1;
        }
    }
    if (ferror(f))
        rc = vcs_fatal_path("read failed: ", mk, err);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = vcs_fatal_path("read failed: ", mk, err);
    regfree(&re);
    if (rc)
        return rc;
    if (seen != 1) {
        fputs("FAIL: dev/test mutation receipt definition missing or "
              "duplicated\n", out);
        bad = 1;
    }
    return bad;
}

/* ── scan_tree() ──────────────────────────────────────────────────────── */

struct vcs_paths {
    char vcs[VCS_PATH], source_identity[VCS_PATH], receipt[VCS_PATH],
         makefile[VCS_PATH], publish_tool[VCS_PATH], session_tool[VCS_PATH];
};

static int vcs_path(char *out, const char *root, const char *rel, FILE *err)
{
    if (ovf(snprintf(out, VCS_PATH, "%s/%s", root, rel), VCS_PATH))
        return vcs_fatal("path too long", err);
    return 0;
}

static int vcs_paths_init(struct vcs_paths *p, const char *root, FILE *err)
{
    int rc = vcs_path(p->vcs, root, "contexts/commons/modules/vcs", err);
    if (rc == 0)
        rc = vcs_path(p->source_identity, root, "tools/dev/source-identity.sh", err);
    if (rc == 0)
        rc = vcs_path(p->receipt, root,
                      "engine/composition/src/consensus_state_producer_receipt.c", err);
    if (rc == 0)
        rc = vcs_path(p->makefile, root, "Makefile", err);
    if (rc == 0)
        rc = vcs_path(p->publish_tool, root, "tools/dev/publish-build-alias.sh", err);
    if (rc == 0)
        rc = vcs_path(p->session_tool, root, "tools/dev/build-epoch-session.sh", err);
    return rc;
}

static int vcs_need(const char *path, int dir, FILE *err)
{
    struct stat st;
    if (stat(path, &st) == 0 && (dir ? S_ISDIR(st.st_mode) : 1))
        return 0;
    return vcs_fatal_path("missing authority surface: ", path, err);
}

static int vcs_surfaces_present(const struct vcs_paths *p, FILE *err)
{
    int rc = vcs_need(p->vcs, 1, err);
    if (rc == 0)
        rc = vcs_need(p->source_identity, 0, err);
    if (rc == 0)
        rc = vcs_need(p->receipt, 0, err);
    if (rc == 0)
        rc = vcs_need(p->makefile, 0, err);
    if (rc == 0)
        rc = vcs_need(p->publish_tool, 0, err);
    if (rc == 0)
        rc = vcs_need(p->session_tool, 0, err);
    return rc;
}

/* hits-then-FAIL idiom for the single-pattern sweeps. */
static int vcs_sweep(const char *path, const char *pat, const char *failmsg,
                     FILE *out, FILE *err)
{
    regex_t re;
    int cr = vcs_comp(&re, pat, 1);
    if (cr)
        return cr;
    int hits = 0;
    int rc = vcs_grep_checked(path, &re, out, err, &hits, 1);
    regfree(&re);
    if (rc)
        return rc;
    if (hits) {
        fprintf(out, "%s\n", failmsg);
        return 1;
    }
    return 0;
}

static const char *const k_authority_rel[] = {
    "engine/composition/src/consensus_state_bundle_validate.c",
    "engine/composition/src/consensus_state_producer_receipt.c",
    "engine/composition/src/consensus_state_producer_status.c",
    "engine/composition/src/consensus_state_snapshot_candidate.c",
    "engine/composition/src/consensus_state_snapshot_candidate_validate.c",
    "engine/composition/src/consensus_state_snapshot_export.c",
    "engine/composition/src/consensus_state_snapshot_export_proof.c",
    "engine/composition/src/consensus_state_snapshot_export_write.c",
    "engine/composition/src/consensus_state_snapshot_install.c",
    "engine/composition/src/consensus_state_snapshot_install_activate.c",
    "engine/services/src/consensus_state_publication_cas.c",
    "tools/dev/publish-build-alias.sh",
    "tools/dev/build-epoch-session.sh",
    "tools/dev/build-epoch-key.sh",
    "tools/dev/compile-epoch-object.sh",
    "tools/dev/build-epoch-open-file-identity.sh",
};

/* The loop form the shell uses: one sweep per authority path, the FAIL
 * line naming the path. */
static int vcs_authority_each(const char *root,
                              const char *pat, const char *failfmt,
                              int check_exists, FILE *out, FILE *err)
{
    regex_t re;
    int cr = vcs_comp(&re, pat, 1);
    if (cr)
        return cr;
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_authority_rel / sizeof k_authority_rel[0]; i++) {
        char path[VCS_PATH];
        rc = vcs_path(path, root, k_authority_rel[i], err);
        if (rc)
            break;
        if (check_exists) {
            rc = vcs_need(path, 0, err);
            if (rc)
                break;
        }
        int hits = 0;
        rc = vcs_grep_checked(path, &re, out, err, &hits, 1);
        if (rc == 0 && hits) {
            fprintf(out, failfmt, path);
            rc = 1;
        }
    }
    regfree(&re);
    return rc;
}

static int vcs_authority_c_each(const char *root,
                                FILE *out, FILE *err)
{
    regex_t re;
    int cr = vcs_comp(&re, "zcl_build_commit(_full)?[[:space:]]*\\(", 1);
    if (cr)
        return cr;
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < 11; i++) {
        char path[VCS_PATH];
        rc = vcs_path(path, root, k_authority_rel[i], err);
        if (rc)
            break;
        int hits = 0;
        rc = vcs_grep_checked(path, &re, out, err, &hits, 1);
        if (rc == 0 && hits) {
            fprintf(out, "FAIL: display-only Git commit entered authority "
                         "surface: %s\n", path);
            rc = 1;
        }
    }
    regfree(&re);
    return rc;
}

static int vcs_receipt_checked(const struct vcs_paths *p, FILE *out, FILE *err)
{
    int rc = vcs_sweep(p->receipt, "zcl_build_commit_full[[:space:]]*\\(",
                       "FAIL: producer receipt writer still derives authority "
                       "from Git SHA-1", out, err);
    if (rc)
        return rc;
    regex_t re;
    int cr = vcs_comp(&re, "zcl_build_source_id_sha256[[:space:]]*\\(", 0);
    if (cr)
        return cr;
    int hits = 0;
    rc = vcs_grep_checked(p->receipt, &re, out, err, &hits, 0);
    regfree(&re);
    if (rc)
        return rc;
    if (hits == 0) {
        fputs("FAIL: producer receipt writer has no SHA-256 source identity "
              "input\n", out);
        return 1;
    }
    return 0;
}

static int vcs_makefile_checked(const struct vcs_paths *p, FILE *out, FILE *err)
{
    int rc = vcs_record_lines_ok(p->makefile, out, err);
    if (rc == 0)
        rc = ipv_rules_checked(p->makefile, out, err);
    if (rc == 0)
        rc = vcs_delegation_checked(p->publish_tool, p->session_tool, out, err);
    if (rc == 0)
        rc = vcs_mutation_confined(p->makefile, out, err);
    return rc;
}

static int vcs_selftest_wired(const struct vcs_paths *p, FILE *out, FILE *err)
{
    regex_t re;
    int cr = vcs_comp(&re, "tools/dev/source-identity-selftest\\.sh", 0);
    if (cr)
        return cr;
    int hits = 0;
    int rc = vcs_grep_checked(p->makefile, &re, out, err, &hits, 0);
    regfree(&re);
    if (rc)
        return rc;
    if (hits == 0) {
        fputs("FAIL: source identity regression suite is not wired into lint\n", out);
        return 1;
    }
    return 0;
}

static int vcs_no_baked_commit(const struct vcs_paths *p, FILE *out, FILE *err)
{
    regex_t re;
    int cr = vcs_comp(&re, "-DZCL_BUILD_COMMIT(_FULL)?=", 0);
    if (cr)
        return cr;
    int hits = 0;
    int rc = vcs_grep_checked(p->makefile, &re, out, err, &hits, 0);
    regfree(&re);
    if (rc)
        return rc;
    if (hits) {
        fputs("FAIL: Git commit text is baked into exact executable/receipt "
              "authority\n", out);
        return 1;
    }
    return 0;
}

static int vcs_scan_tree(const char *root, FILE *out, FILE *err)
{
    struct vcs_paths p;
    int rc = vcs_paths_init(&p, root, err);
    if (rc == 0)
        rc = vcs_surfaces_present(&p, err);
    if (rc == 0)
        rc = vcs_sweep(p.vcs, "sha[-_]?1",
                       "FAIL: contexts/commons/modules/vcs must use "
                       "SHA3-256/SHA-256, never SHA-1", out, err);
    if (rc == 0) {
        regex_t re;
        rc = vcs_comp(&re, "(^|[^[:alnum:]_.-])git[[:space:]]", 0);
        if (rc == 0) {
            rc = vcs_git_calls_allowed(p.source_identity, &re, out, err);
            regfree(&re);
        }
    }
    if (rc == 0)
        rc = vcs_sweep(p.source_identity,
                       "sha1(sum)?|sha-1|zcl\\.dev_source_identity\\.v1",
                       "FAIL: source identity names legacy SHA-1/v1 authority",
                       out, err);
    if (rc == 0)
        rc = vcs_authority_each(root,
                                "([[:alnum:]_]*sha1[[:alnum:]_]*[[:space:]]*\\(|sha1sum|SHA1[[:space:]]*\\()",
                                "FAIL: SHA-1 primitive in authority surface: %s\n",
                                1, out, err);
    if (rc == 0)
        rc = vcs_authority_c_each(root, out, err);
    if (rc == 0)
        rc = vcs_receipt_checked(&p, out, err);
    if (rc == 0)
        rc = vcs_makefile_checked(&p, out, err);
    if (rc == 0)
        rc = vcs_selftest_wired(&p, out, err);
    if (rc == 0)
        rc = vcs_no_baked_commit(&p, out, err);
    return rc;
}

/* ── fixture self-test (the shell script's self_test) ─────────────────── */

static const char k_fx_object[] = "void sha3_only(void);\n";
static const char k_fx_source_identity[] =
    "#!/bin/sh\n"
    "git ls-files --stage -z --\n"
    "sha256sum\n";
static const char k_fx_receipt[] =
    "const char *zcl_build_source_id_sha256(void);\n"
    "void receipt(void) { (void)zcl_build_source_id_sha256(); }\n";
static const char k_fx_authority[] = "void authority_sha256_only(void);\n";
static const char k_fx_cas[] = "void publication_sha256_only(void);\n";
static const char k_fx_publish[] =
    "#!/bin/sh\n"
    "\"$SESSION_TOOL\" verify\n"
    "mv -f -- \"$TMP\" \"$ALIAS\"\n";
static const char k_fx_session[] =
    "#!/bin/sh\n"
    "\"$VERIFY_TOOL\" verify-record\n";
static const char k_fx_sha256tool[] = "#!/bin/sh\nsha256sum\n";
static const char k_fx_truetool[] = "#!/bin/sh\ntrue\n";
static const char k_fx_makefile[] =
    "BUILD_SOURCE_RECORD := $(shell tools/dev/source-identity.sh capture-record)\n"
    "BUILD_SOURCE_ID := $(word 1,$(BUILD_SOURCE_RECORD))\n"
    "BUILD_CLEAN := $(word 2,$(BUILD_SOURCE_RECORD))\n"
    "BUILD_MUTATION := $(word 3,$(BUILD_SOURCE_RECORD))\n"
    "DEV_SOURCE_RECEIPT_CPPFLAGS = -DZCL_BUILD_SOURCE_MUTATION=\\\"$(BUILD_MUTATION)\\\"\n"
    "$(eval $(call BUILD_NODE_TOOL,test_zcl,test.c,,-DZCL_TESTING $(DEV_SOURCE_RECEIPT_CPPFLAGS) $(EXTRA_TEST_FLAGS)))\n"
    "$(eval $(call BUILD_NODE_TOOL,test_parallel_wpo,test.c,,-DZCL_TESTING $(DEV_SOURCE_RECEIPT_CPPFLAGS)))\n"
    "$(DEV_OBJ_DIR)/platform/modules/util/src/clientversion.o: DEV_COMPILE_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)\n"
    "artifact: $(BUILD_IDENTITY_STAMP)\n"
    "\t@set -eu; \\\n"
    "\ttmp=\"$@.tmp\"; \\\n"
    "\tcc -DZCL_BUILD_SOURCE_ID -o \"$$tmp\" source.c; \\\n"
    "\ttools/dev/source-identity.sh verify-record \"$(BUILD_SOURCE_ID)\" \"$(BUILD_CLEAN)\" \"$(BUILD_MUTATION)\"; \\\n"
    "\tmv -f -- \"$$tmp\" \"$@\"\n"
    "lint: ; @tools/dev/source-identity-selftest.sh\n";

static int vcs_fx_write(const char *root, const char *rel, const char *text)
{
    char path[VCS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    return csr_write(path, text);
}

static int vcs_fx_build(const char *root)
{
    int rc = vcs_fx_write(root, "contexts/commons/modules/vcs/src/object.c",
                          k_fx_object);
    if (rc == 0)
        rc = vcs_fx_write(root, "tools/dev/source-identity.sh",
                          k_fx_source_identity);
    if (rc == 0)
        rc = vcs_fx_write(root,
                          "engine/composition/src/consensus_state_producer_receipt.c",
                          k_fx_receipt);
    if (rc == 0)
        rc = vcs_fx_write(root, "engine/services/src/consensus_state_publication_cas.c",
                          k_fx_cas);
    if (rc == 0)
        rc = vcs_fx_write(root, "tools/dev/publish-build-alias.sh", k_fx_publish);
    if (rc == 0)
        rc = vcs_fx_write(root, "tools/dev/build-epoch-session.sh", k_fx_session);
    if (rc == 0)
        rc = vcs_fx_write(root, "tools/dev/build-epoch-key.sh", k_fx_sha256tool);
    if (rc == 0)
        rc = vcs_fx_write(root, "tools/dev/compile-epoch-object.sh", k_fx_sha256tool);
    if (rc == 0)
        rc = vcs_fx_write(root, "tools/dev/build-epoch-open-file-identity.sh",
                          k_fx_truetool);
    if (rc == 0)
        rc = vcs_fx_write(root, "Makefile", k_fx_makefile);
    return rc;
}

static int vcs_fx_authority_files(const char *root)
{
    static const char *const rel[] = {
        "engine/composition/src/consensus_state_bundle_validate.c",
        "engine/composition/src/consensus_state_producer_status.c",
        "engine/composition/src/consensus_state_snapshot_candidate.c",
        "engine/composition/src/consensus_state_snapshot_candidate_validate.c",
        "engine/composition/src/consensus_state_snapshot_export.c",
        "engine/composition/src/consensus_state_snapshot_export_proof.c",
        "engine/composition/src/consensus_state_snapshot_export_write.c",
        "engine/composition/src/consensus_state_snapshot_install.c",
        "engine/composition/src/consensus_state_snapshot_install_activate.c",
    };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof rel / sizeof rel[0]; i++)
        rc = vcs_fx_write(root, rel[i], k_fx_authority);
    return rc;
}

/* One self-test step: mutate (or NULL for the base fixture), expect rc.
 * Out/err of the scan are diverted into tmpfiles like the shell's
 * >/dev/null 2>&1. Returns 0 when the expectation holds. */
static int vcs_st_case(const char *root, const char *rel, const char *text,
                       int want)
{
    if (rel && vcs_fx_write(root, rel, text))
        return 1;
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    int rc = vcs_scan_tree(root, out, err);
    fclose(out);
    fclose(err);
    return rc != want;
}

static const char k_fx_mk_z23_escape[] =
    "$(eval $(call BUILD_NODE_TOOL,z23,node.c,,-DZCL_TESTING $(DEV_SOURCE_RECEIPT_CPPFLAGS) $(EXTRA_TEST_FLAGS)))\n";
static const char k_fx_mk_receipt_flags[] =
    "BUILD_IDENTITY_CPPFLAGS += $(DEV_SOURCE_RECEIPT_CPPFLAGS)\n";
static const char k_fx_obj_prefixed[] =
    "void prefixed(void) { EVP_sha1(); mbedtls_sha1_init();\n"
    " git_sha1_entry(); }\n";
static const char k_fx_receipt_commit[] =
    "const char *zcl_build_source_id_sha256(void);\n"
    "const char *zcl_build_commit_full(void);\n"
    "void receipt(void) { (void)zcl_build_source_id_sha256();\n"
    " (void)zcl_build_commit_full(); }\n";
static const char k_fx_mk_baked[] =
    "CFLAGS += -DZCL_BUILD_COMMIT_FULL=\"deadbeef\"\n";
static const char k_fx_mk_unverified[] =
    "unverified: $(BUILD_IDENTITY_STAMP)\n"
    "\t@cp source.c \"$@\"\n";
static const char k_fx_git_camouflage[] =
    "#!/bin/sh\n"
    "git ls-files -v -z && git status\n"
    "sha256sum\n";

static int vcs_st_git_variant(const char *root, const char *gitline)
{
    char text[512];
    int n = snprintf(text, sizeof text, "#!/bin/sh\n"
                     "git ls-files --stage -z --\nsha256sum\n%s\n", gitline);
    if (ovf(n, sizeof text))
        return 1;
    return vcs_st_case(root, "tools/dev/source-identity.sh", text, 1);
}

static int vcs_st_unreadable(const char *root)
{
    char path[VCS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root,
                     "contexts/commons/modules/vcs/src/object.c"), sizeof path))
        return 1;
    if (chmod(path, 0) != 0)
        return 1;
    int bad = vcs_st_case(root, NULL, NULL, 2);
    if (chmod(path, 0600) != 0)
        return 1;
    return bad;
}

static int vcs_st_concat(const char *a, const char *b, char *out, size_t cap)
{
    return ovf(snprintf(out, cap, "%s%s", a, b), cap) != 0;
}

static int vcs_st_makefile_cases(const char *root, const char **failmsg)
{
    static char mkbuf[sizeof k_fx_makefile + 256];
    if (vcs_st_concat(k_fx_makefile, k_fx_mk_z23_escape, mkbuf, sizeof mkbuf)
        || vcs_st_case(root, "Makefile", mkbuf, 1)) {
        *failmsg = "host-local mutation receipt escaped into a non-test target";
        return 1;
    }
    if (vcs_st_concat(k_fx_makefile, k_fx_mk_receipt_flags, mkbuf, sizeof mkbuf)
        || vcs_st_case(root, "Makefile", mkbuf, 1)) {
        *failmsg = "host-local mutation receipt escaped into release identity flags";
        return 1;
    }
    if (vcs_st_concat(k_fx_makefile, k_fx_mk_baked, mkbuf, sizeof mkbuf)
        || vcs_st_case(root, "Makefile", mkbuf, 1)) {
        *failmsg = "baked Git commit executable-authority fixture passed";
        return 1;
    }
    if (vcs_st_concat(k_fx_makefile, k_fx_mk_unverified, mkbuf, sizeof mkbuf)
        || vcs_st_case(root, "Makefile", mkbuf, 1)) {
        *failmsg = "unverified identity-bearing publication fixture passed";
        return 1;
    }
    return 0;
}

static int vcs_st_sha1_cases(const char *root, const char **failmsg)
{
    if (vcs_st_unreadable(root)) {
        *failmsg = "unreadable scanned file false-greened the hard gate";
        return 1;
    }
    if (vcs_st_case(root, "contexts/commons/modules/vcs/src/object.c",
                    "void sha3_only(void);\nvoid bad(void) { sha1_init(0); }\n", 1)) {
        *failmsg = "contexts/commons/modules/vcs SHA-1 fixture passed";
        return 1;
    }
    if (vcs_st_case(root, "contexts/commons/modules/vcs/src/object.c",
                    k_fx_obj_prefixed, 1)) {
        *failmsg = "prefixed contexts/commons/modules/vcs SHA-1 API fixtures passed";
        return 1;
    }
    return 0;
}

static int vcs_st_git_cases(const char *root, const char **failmsg)
{
    static const char *const bad_lines[] = {
        "git rev-parse HEAD", "git -C . rev-parse HEAD", "git rev-parse main",
        "git log -1 --format=%H", "git ls-tree HEAD",
    };
    static const char *const msgs[] = {
        "Git HEAD source-identity fixture passed",
        "Git -C HEAD source-identity fixture passed",
        "alternate Git revision source-identity fixture passed",
        "Git log object-id source-identity fixture passed",
        "Git ls-tree object-id source-identity fixture passed",
    };
    for (size_t i = 0; i < sizeof bad_lines / sizeof bad_lines[0]; i++) {
        if (vcs_st_git_variant(root, bad_lines[i])) {
            *failmsg = msgs[i];
            return 1;
        }
    }
    if (vcs_st_case(root, "tools/dev/source-identity.sh",
                    k_fx_git_camouflage, 1)) {
        *failmsg = "Git camouflage source-identity fixture passed";
        return 1;
    }
    if (vcs_st_case(root,
                    "engine/composition/src/consensus_state_producer_receipt.c",
                    k_fx_receipt_commit, 1)) {
        *failmsg = "Git commit receipt-authority fixture passed";
        return 1;
    }
    return 0;
}

static int vcs_fixture_selftest(const char **failmsg)
{
    char tmpl[] = "/tmp/z23-lint-vcssha1-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    int bad = vcs_fx_build(root) || vcs_fx_authority_files(root);
    if (!bad && vcs_st_case(root, NULL, NULL, 0)) {
        bad = 1;
        *failmsg = "known-good fixture failed";
    }
    if (!bad)
        bad = vcs_st_makefile_cases(root, failmsg);
    if (!bad)
        bad = vcs_st_sha1_cases(root, failmsg);
    if (!bad)
        bad = vcs_st_git_cases(root, failmsg);
    (void)rap_rm_rf(root);
    return bad;
}

int check_vcs_no_sha1_selftest(void)
{
    const char *msg = "fixture setup failed";
    int bad = vcs_fixture_selftest(&msg);
    if (bad)
        fprintf(stderr, "check_vcs_no_sha1 selftest: FAIL — %s\n", msg);
    return st_ok(bad, "check_vcs_no_sha1 selftest: OK\n");
}

/* ── CLI ──────────────────────────────────────────────────────────────── */

static int vcs_default_root(char *buf, size_t cap)
{
    const char *e = getenv("ZCL_VCS_SHA1_ROOT");
    if (e && e[0]) {
        if (strlen(e) >= cap)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(buf, e, strlen(e) + 1);
        return 0;
    }
    return cic_repo_root(buf, cap);
}

int check_vcs_no_sha1_run(int argc, char **argv)
{
    if (argc >= 1) {
        if (strcmp(argv[0], "--self-test") == 0) {
            const char *msg = "fixture setup failed";
            if (vcs_fixture_selftest(&msg)) {
                char m[256];
                if (ovf(snprintf(m, sizeof m, "%s", msg), sizeof m))
                    return 2;
                return vcs_fatal(m, stderr);
            }
            fputs("check_vcs_no_sha1: self-test PASS\n", stdout);
            return 0;
        }
        if (strcmp(argv[0], "--scan") != 0) {
            char m[256];
            if (ovf(snprintf(m, sizeof m, "unknown argument: %s", argv[0]),
                    sizeof m))
                return 2;
            return vcs_fatal(m, stderr);
        }
    }
    char root[VCS_PATH];
    int rc = vcs_default_root(root, sizeof root);
    if (rc)
        return rc;
    struct stat st;
    if (stat(root, &st) != 0)
        return vcs_fatal_path("cannot enter ", root, stderr);
    const char *msg = "fixture setup failed";
    if (vcs_fixture_selftest(&msg)) {
        char m[256];
        if (ovf(snprintf(m, sizeof m, "%s", msg), sizeof m))
            return 2;
        return vcs_fatal(m, stderr);
    }
    rc = vcs_scan_tree(root, stdout, stderr);
    if (rc)
        return rc;
    fputs("check_vcs_no_sha1: clean — ZVCS/producer-source authority is "
          "SHA-1-free\n", stdout);
    return 0;
}
