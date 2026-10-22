/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of check-api-reference-generated. Copies exactly what the
 * gate reads into a scratch tree, proves the gate passes on it, then removes a
 * command leaf row and a template section from the generated reference and
 * proves each is refused by name, so the gate cannot decay into a no-op. It
 * also proves that an unwritable reference path is fatal and that a scratch directory
 * which cannot be created (overlong or unwritable TMPDIR) removes nothing.
 * Every fixture lives under a private directory this selftest creates.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_api_reference_generated_priv.h"
#include "lintc.h"
#include "lintc_sig.h"

enum { ARS_LOG = 65536, ARS_SEG_STEP = 100, ARS_SEG_SLACK = 101 };

static const char ars_name[] = "check_api_reference_generated selftest";

static const char *const ars_fixed[] = {
    "engine/modules/kernel/include/kernel/command_registry.h",
    "platform/modules/json/include/json/json.h",
    "platform/modules/base/include/base/cleanse.h",
};

static int ars_copy(const char *root, const char *rel)
{
    char dst[PATH_MAX + 256], buf[8192];
    size_t n;
    int rc = 0;
    snprintf(dst, sizeof dst, "%s/%s", root, rel);
    FILE *in = fopen(rel, "rb");
    if (!in)
        return die("z23-lint: cannot open %s\n", rel);
    char *slash = strrchr(dst, '/');
    *slash = '\0';
    rc = csr_mkdirs(dst);
    *slash = '/';
    FILE *out = rc ? NULL : fopen(dst, "wb");
    while (out && rc == 0 && (n = fread(buf, 1, sizeof buf, in)) > 0)
        if (fwrite(buf, 1, n, out) != n)
            rc = die("z23-lint: write failed: %s\n", dst);
    if (!out && rc == 0)
        rc = die("z23-lint: cannot open %s\n", dst);
    if (rc == 0 && ferror(in))
        rc = die("z23-lint: read failed: %s\n", rel);
    if (out && fclose(out) != 0 && rc == 0)
        rc = die("z23-lint: write failed: %s\n", dst);
    fclose(in);
    return rc;
}

static int ars_populate(const char *root)
{
    struct arg_defs d;
    int rc = arg_def_list(&d);
    for (size_t i = 0; rc == 0 && i < d.n; i++)
        rc = ars_copy(root, d.path[i]);
    for (size_t i = 0; rc == 0 && i < sizeof ars_fixed / sizeof ars_fixed[0]; i++)
        rc = ars_copy(root, ars_fixed[i]);
    const char *const own[] = { arg_gen_src, arg_template };
    for (size_t i = 0; rc == 0 && i < sizeof own / sizeof own[0]; i++)
        rc = ars_copy(root, own[i]);
    return rc;
}

/* Runs the gate in root with all output captured into log (a tmpfile). */
static int ars_run(const char *root, const char *home, FILE *log)
{
    struct arg_io io = { log, log };
    if (chdir(root) != 0)
        return 2;
    int rc = arg_gate(&io);
    if (chdir(home) != 0)
        return 2;
    fflush(log);
    rewind(log);
    return rc;
}

/* Replaces the first occurrence of `from` in the generated reference with the
 * same-length `to`; 1 when it was not found or the file could not be rewritten. */
static int ars_tamper(const char *root, const char *from, const char *to)
{
    char path[PATH_MAX + 64];
    snprintf(path, sizeof path, "%s/%s", root, arg_doc);
    char *text = arg_slurp(path);
    char *at = text ? strstr(text, from) : NULL;
    int bad = !at;
    if (at) {
        memcpy(at, to, strlen(to));
        FILE *out = fopen(path, "wb");
        bad = !out || fwrite(text, 1, strlen(text), out) != strlen(text);
        if (out && fclose(out) != 0)
            bad = 1;
    }
    free(text);
    if (bad)
        fprintf(stderr, "%s: FAIL — cannot plant %s in the generated reference;\n"
                "  the fixture assumption broke.\n", ars_name, from);
    return bad;
}

/* Runs arg_verify in root; the tampered reference must fail and name `needle`. */
static int ars_verify_fails(const char *root, const char *home, const char *needle)
{
    char text[ARS_LOG], entries[24];
    struct arg_defs d;
    FILE *log = tmpfile();
    if (!log)
        return die("z23-lint: cannot create a temporary file\n", "");
    struct arg_io io = { log, log };
    int rc = chdir(root) != 0 || arg_def_list(&d) != 0 ? 2 : arg_verify(&io, &d, entries, sizeof entries);
    if (chdir(home) != 0)
        rc = 2;
    fflush(log);
    rewind(log);
    if (csr_slurp(log, text, sizeof text) != 0)
        text[0] = '\0';
    fclose(log);
    int bad = rc != 1 || !strstr(text, needle);
    if (bad) {
        fprintf(stderr, "%s: FAIL — a reference missing %s was not refused by name (exit %d):\n",
                ars_name, needle, rc);
        arg_indent(stderr, text, 0);
    }
    return bad;
}

/* The tamper test: a missing leaf row and a missing template section each fail. */
static int ars_tampers(const char *root, const char *home)
{
    static const char leaf[] = "`core status`", leaf_bad[] = "`core_status`";
    static const char head[] = "## Aliases", head_bad[] = "## Aliaxes";
    if (ars_tamper(root, leaf, leaf_bad) || ars_verify_fails(root, home, "core status"))
        return 1;
    if (ars_tamper(root, leaf_bad, leaf) || ars_tamper(root, head, head_bad))
        return 1;
    return ars_verify_fails(root, home, head);
}

/* The gate's exit code with its captured output in text; 2 when the capture fails. */
static int ars_gate_text(const char *root, const char *home, char *text, size_t cap)
{
    FILE *log = tmpfile();
    if (!log)
        return die("z23-lint: cannot create a temporary file\n", "");
    int rc = ars_run(root, home, log);
    if (csr_slurp(log, text, cap) != 0)
        text[0] = '\0';
    fclose(log);
    return rc;
}

static int ars_expect_clean(const char *root, const char *home)
{
    char text[ARS_LOG];
    int rc = ars_gate_text(root, home, text, sizeof text);
    if (rc != 0) {
        fprintf(stderr, "%s: FAIL — the gate did not\n  pass on an unmodified copy of the tree (%s):\n",
                ars_name, arg_doc);
        arg_indent(stderr, text, 0);
    }
    return rc != 0;
}

/* A reference that cannot be read must end the gate with a fatal naming it. */
static int ars_read_error(const char *root, const char *home)
{
    char path[PATH_MAX + 64], text[ARS_LOG];
    snprintf(path, sizeof path, "%s/%s", root, arg_doc);
    if (unlink(path) != 0 || mkdir(path, 0700) != 0)
        return die("z23-lint: cannot stage an unreadable reference\n", "");
    int rc = ars_gate_text(root, home, text, sizeof text);
    int bad = rc != 2 || !strstr(text, "FATAL") || !strstr(text, arg_doc);
    if (bad) {
        fprintf(stderr, "%s: FAIL — an unreadable reference did not end the gate with a\n"
                "  fatal naming %s (exit %d):\n", ars_name, arg_doc, rc);
        arg_indent(stderr, text, 0);
    }
    return bad;
}

static int ars_is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* With TMPDIR at tmp the scratch directory cannot be created: the gate must exit 2,
 * leave no half-built name behind, and not remove the directory at victim. */
static int ars_scratch_refused(const char *root, const char *home, const char *tmp,
                               const char *victim, const char *what)
{
    char text[ARS_LOG], saved[PATH_MAX];
    struct arg_scratch s;
    const char *prev = getenv("TMPDIR");
    snprintf(saved, sizeof saved, "%s", prev ? prev : "");
    setenv("TMPDIR", tmp, 1);
    int opened = arg_open_scratch(&s);
    int rc = ars_gate_text(root, home, text, sizeof text);
    if (prev)
        setenv("TMPDIR", saved, 1);
    else
        unsetenv("TMPDIR");
    int bad = opened == 0 || s.dir[0] != '\0' || rc != 2 || !ars_is_dir(victim);
    if (bad)
        fprintf(stderr, "%s: FAIL — %s: scratch directory not refused cleanly (open %d,\n"
                "  leftover name length %zu, exit %d, sibling kept %d)\n", ars_name, what, opened,
                strlen(s.dir), rc, ars_is_dir(victim));
    return bad;
}

/* Extends path with directories of at most 200 characters until it is target long. */
static int ars_mkdeep(char *path, size_t target)
{
    size_t len = strlen(path);
    while (len < target) {
        size_t seg = target - len > ARS_SEG_STEP + ARS_SEG_SLACK ? ARS_SEG_STEP : target - len - 1;
        path[len] = '/';
        memset(path + len + 1, 'd', seg);
        len += seg + 1;
        path[len] = '\0';
        if (mkdir(path, 0700) != 0)
            return -1;
    }
    return 0;
}

/* An overlong TMPDIR truncates the scratch name to a directory that exists. */
static int ars_truncation(const char *priv, const char *root, const char *home)
{
    char tmp[PATH_MAX + 64], victim[PATH_MAX + 128], physical[PATH_MAX];
    static const char name[] = "/zcl-apiref.XXXXXX";
    /* Darwin's /var alias adds /private during pathname resolution. Count
     * the physical prefix so the planted victim stays below PATH_MAX. */
    if (!realpath(priv, physical))
        return die("z23-lint: cannot resolve the scratch directory\n", "");
    snprintf(tmp, sizeof tmp, "%s/long", physical);
    if (mkdir(tmp, 0700) != 0 || ars_mkdeep(tmp, PATH_MAX - (sizeof name - 1)) != 0)
        return die("z23-lint: cannot stage an overlong TMPDIR\n", "");
    snprintf(victim, sizeof victim, "%s%.*s", tmp, (int)sizeof name - 2, name);
    if (mkdir(victim, 0700) != 0)
        return die("z23-lint: cannot stage the truncated name\n", "");
    return ars_scratch_refused(root, home, tmp, victim, "overlong TMPDIR");
}

/* An unwritable TMPDIR makes mkdtemp fail. */
static int ars_denied(const char *priv, const char *root, const char *home)
{
    char tmp[PATH_MAX + 64], victim[PATH_MAX + 128];
    snprintf(tmp, sizeof tmp, "%s/denied", priv);
    snprintf(victim, sizeof victim, "%s/keep", tmp);
    if (mkdir(tmp, 0700) != 0 || mkdir(victim, 0700) != 0 || chmod(tmp, 0500) != 0)
        return die("z23-lint: cannot stage an unwritable TMPDIR\n", "");
    int bad = ars_scratch_refused(root, home, tmp, victim, "unwritable TMPDIR");
    (void)chmod(tmp, 0700);
    return bad;
}

static int ars_cases(const char *priv, const char *root, const char *home)
{
    if (ars_populate(root) != 0)
        return 1;
    if (ars_expect_clean(root, home) || lsc_pending())
        return 1;
    if (ars_tampers(root, home) != 0)
        return 1;
    return ars_truncation(priv, root, home)
        || ars_denied(priv, root, home) || ars_read_error(root, home);
}

int check_api_reference_generated_selftest(void)
{
    char home[PATH_MAX], root[PATH_MAX + 32], sandbox[PATH_MAX + 48];
    if (cic_repo_root(home, sizeof home) != 0 || chdir(home) != 0 || lsc_install() != 0)
        return 2;
    if (snprintf(root, sizeof root, "%s/zcl-apiref-selftest.XXXXXX",
                 env_or("TMPDIR", arg_tmp_default)) >= (int)sizeof root || !mkdtemp(root))
        return die("z23-lint: cannot create a scratch directory\n", "");
    snprintf(sandbox, sizeof sandbox, "%s/repo", root);
    int rc = csr_mkdirs(sandbox) != 0 ? 1 : ars_cases(root, sandbox, home);
    int sig = lsc_pending();
    (void)rap_rm_rf(root);
    if (sig)
        lsc_finish(sig);
    if (rc == 0)
        printf("%s: PASS — clean tree passes, a generated reference missing a leaf row or a template\n  section is refused by name,\n"
               "  an unwritable reference path is fatal, a refused scratch directory removes nothing\n",
               ars_name);
    return rc;
}
