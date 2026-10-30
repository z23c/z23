/* Copyright 2026 Rhett Creeton - Apache License 2.0
 *
 * purpose: gate check_ship_remote_transaction — hermetic proof of the
 * immutable remote release transaction. Ported from
 * tools/lint/check_ship_remote_transaction.sh (deleted). It compiles the
 * literal fixture (tools/lint/ship_remote_fixture.c) at -O0 and -O2,
 * extracts the literal remote programs out of tools/ship.sh, runs them
 * with a fake user service and real fixture processes, and proves the
 * immutable-mismatch, activation-lock, partial-stage, reload/restart
 * fault, drop-in precedence, shadowed-ExecStart refusal and rollback
 * paths. No network or production state is touched. Runs from the
 * repository root. Helpers live in gate_ship_remote_transaction_util.c;
 * selftest in gate_ship_remote_transaction_selftest.c.
 *
 * Exit codes mirror the shell original: 0 pass (one PASS line on stdout),
 * 1 a proof failed (message on stderr), 2 an infrastructure error.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_ship_remote_transaction_priv.h"


/* ---- setup ---- */

static int srt_cc(const struct srt_ctx *c, const char *opt, const char *out)
{
    (void)c;
    char *const av[10] = { (char *)"cc", (char *)"-std=c2x", (char *)"-Wall",
        (char *)"-Wextra", (char *)"-Werror", (char *)opt,
        (char *)"tools/lint/ship_remote_fixture.c", (char *)"-o", (char *)out,
        NULL };
    int rc = 1;
    if (srt_run(av, NULL, NULL, NULL, 0, &rc) != 0 || rc != 0) {
        fprintf(stderr, "%s: fixture compile failed (%s)\n", k_srt_gate, out);
        return 2;
    }
    return 0;
}

const char *srt_tmpdir(void)
{
    return env_or("TMPDIR", "/tmp");
}

static int srt_setup_build(struct srt_ctx *c)
{
    const char *td = srt_tmpdir();
    char tmpl[SRT_PATH], rp[4097];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/zcl-ship-remote-test.XXXXXX", td),
            sizeof tmpl))
        return 2;
    if (!mkdtemp(tmpl)) {
        fprintf(stderr, "%s: mkdtemp failed\n", k_srt_gate);
        return 2;
    }
    if (!realpath(tmpl, rp) || ovf(snprintf(c->tmp, sizeof c->tmp, "%s", rp), sizeof c->tmp)) {
        fprintf(stderr, "%s: realpath failed for %s\n", k_srt_gate, tmpl);
        return 2;
    }
    if (ovf(snprintf(c->old, sizeof c->old, "%s/old", c->tmp), sizeof c->old))
        return 2;
    if (ovf(snprintf(c->new, sizeof c->new, "%s/new", c->tmp), sizeof c->new))
        return 2;
    int rc = srt_cc(c, "-O0", c->old);
    if (rc == 0)
        rc = srt_cc(c, "-O2", c->new);
    if (rc)
        return rc;
    char *const av[4] = { c->old, (char *)"init", c->tmp, NULL };
    int st = 1;
    if (srt_run(av, NULL, NULL, NULL, 0, &st) != 0 || st != 0) {
        fprintf(stderr, "%s: fixture init failed\n", k_srt_gate);
        return 2;
    }
    return 0;
}

static int srt_extract(const struct srt_ctx *c, const char *tag,
                       const char *dst)
{
    char marker[64];
    if (ovf(snprintf(marker, sizeof marker, "<<'%s'", tag), sizeof marker))
        return 2;
    char *const av[6] = { (char *)c->old, (char *)"extract",
        (char *)"tools/ship.sh", marker, (char *)tag, NULL };
    int st = 1;
    if (srt_run(av, NULL, NULL, dst, 0, &st) != 0 || st != 0) {
        fprintf(stderr, "%s: extract %s failed\n", k_srt_gate, tag);
        return 2;
    }
    return 0;
}

static int srt_compose(const char *dst, const char *part)
{
    if (srt_write_file(dst, ""))
        return 2;
    if (srt_append_file(dst, "tools/scripts/ship_progress_lib.sh"))
        return 2;
    if (srt_append_file(dst, part))
        return 2;
    return 0;
}

static int srt_setup_scripts(struct srt_ctx *c)
{
    if (ovf(snprintf(c->binding_check, sizeof c->binding_check,
                     "%s/binding-check.sh", c->tmp), sizeof c->binding_check))
        return 2;
    if (ovf(snprintf(c->release_check, sizeof c->release_check,
                     "%s/release-check.sh", c->tmp), sizeof c->release_check))
        return 2;
    if (ovf(snprintf(c->activate, sizeof c->activate, "%s/activate.sh", c->tmp),
            sizeof c->activate))
        return 2;
    if (ovf(snprintf(c->rollback, sizeof c->rollback, "%s/rollback.sh", c->tmp),
            sizeof c->rollback))
        return 2;
    int rc = srt_extract(c, "REMOTE_BINDING_CHECK", c->binding_check);
    if (rc == 0)
        rc = srt_extract(c, "REMOTE_RELEASE_CHECK", c->release_check);
    if (rc)
        return rc;
    char part[SRT_PATH];
    if (ovf(snprintf(part, sizeof part, "%s/activate.part", c->tmp),
            sizeof part))
        return 2;
    rc = srt_extract(c, "REMOTE_SCRIPT", part);
    if (rc == 0)
        rc = srt_compose(c->activate, part);
    if (rc)
        return rc;
    if (ovf(snprintf(part, sizeof part, "%s/rollback.part", c->tmp),
            sizeof part))
        return 2;
    rc = srt_extract(c, "ROLLBACK_SCRIPT", part);
    if (rc == 0)
        rc = srt_compose(c->rollback, part);
    if (rc)
        return rc;
    char *const av[6] = { (char *)"bash", (char *)"-n", c->release_check,
        c->activate, c->rollback, NULL };
    int st = 1;
    if (srt_run(av, NULL, NULL, NULL, 0, &st) != 0 || st != 0) {
        fprintf(stderr, "%s: extracted scripts failed bash -n\n", k_srt_gate);
        return 2;
    }
    return 0;
}

static int srt_set_unit_z23(struct srt_ctx *c)
{
    if (ovf(snprintf(c->node_unit, sizeof c->node_unit, "z23-node.service"),
            sizeof c->node_unit))
        return 2;
    if (ovf(snprintf(c->dropin_dir, sizeof c->dropin_dir,
                     "%s/.config/systemd/user/%s.d", c->home, c->node_unit),
            sizeof c->dropin_dir))
        return 2;
    if (ovf(snprintf(c->dropin, sizeof c->dropin,
                     "%s/zzzzz-z23-ship-release.conf", c->dropin_dir),
            sizeof c->dropin))
        return 2;
    return 0;
}

static int srt_setup_paths(struct srt_ctx *c)
{
    if (srt_sha256_file(c->old, c->old_sha) ||
        srt_sha256_file(c->new, c->new_sha))
        return 2;
    memset(c->source_id, 'a', 64);
    c->source_id[64] = '\0';
    if (ovf(snprintf(c->manifest, sizeof c->manifest, "%s/MANIFEST.sha256",
                     c->tmp), sizeof c->manifest))
        return 2;
    char text[SRT_TEXT];
    if (ovf(snprintf(text, sizeof text,
            "%s  z23\n%s  z23-package-verify\n%s  z23-package-verify-dev\n"
            "%s  zclassic23-package-verify\n%s  zclassic23-package-verify-dev\n",
            c->new_sha, c->new_sha, c->new_sha, c->new_sha, c->new_sha),
            sizeof text))
        return 2;
    if (srt_write_file(c->manifest, text))
        return 2;
    if (srt_sha256_file(c->manifest, c->manifest_sha))
        return 2;
    if (ovf(snprintf(c->home, sizeof c->home, "%s/home", c->tmp),
            sizeof c->home))
        return 2;
    if (ovf(snprintf(c->release, sizeof c->release,
                     "%s/.local/lib/z23/releases/%s", c->home, c->manifest_sha),
            sizeof c->release))
        return 2;
    if (ovf(snprintf(c->incoming, sizeof c->incoming, "%s.incoming.test-run",
                     c->release), sizeof c->incoming))
        return 2;
    if (ovf(snprintf(c->mockbin, sizeof c->mockbin, "%s/mockbin", c->tmp),
            sizeof c->mockbin))
        return 2;
    if (ovf(snprintf(c->state_file, sizeof c->state_file, "%s/fixture.state",
                     c->tmp), sizeof c->state_file))
        return 2;
    if (ovf(snprintf(c->pidfile, sizeof c->pidfile, "%s/service.pid", c->tmp),
            sizeof c->pidfile))
        return 2;
    return srt_set_unit_z23(c);
}

static int srt_setup_state(struct srt_ctx *c)
{
    char releases[SRT_PATH];
    if (ovf(snprintf(releases, sizeof releases, "%s/.local/lib/z23/releases",
                     c->home), sizeof releases))
        return 2;
    if (srt_mkdirp(c->mockbin) || srt_mkdirp(c->dropin_dir) ||
        srt_mkdirp(releases))
        return 2;
    char sysctl[SRT_PATH], body[2 * SRT_PATH];
    if (ovf(snprintf(sysctl, sizeof sysctl, "%s/systemctl", c->mockbin),
            sizeof sysctl))
        return 2;
    if (ovf(snprintf(body, sizeof body,
                     "#!/bin/sh\nexec \"%s\" systemctl \"%s\" \"$@\"\n",
                     c->old, c->state_file), sizeof body))
        return 2;
    if (srt_write_exec(sysctl, body))
        return 2;
    return srt_fixture_state_pub(c, "", "", "");
}

static int srt_setup(struct srt_ctx *c)
{
    int rc = srt_setup_build(c);
    if (rc == 0)
        rc = srt_setup_scripts(c);
    if (rc == 0)
        rc = srt_setup_paths(c);
    if (rc == 0)
        rc = srt_setup_state(c);
    return rc;
}

/* ---- fixture drivers (used by the phases) ---- */

int srt_fixture_state_pub(struct srt_ctx *c, const char *f1, const char *f2,
                          const char *f3)
{
    char text[4 * SRT_PATH];
    if (ovf(snprintf(text, sizeof text, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
                     c->tmp, c->node_unit, f3, c->source_id, f1, f2,
                     c->manifest_sha), sizeof text))
        return 2;
    return srt_write_file(c->state_file, text) == 0 ? 0 : 2;
}

int srt_invoke_activate(struct srt_ctx *c, const char *fault,
                               const char *out, int merge, int *rc)
{
    int r0 = srt_fixture_state_pub(c, fault ? fault : "", "", "");
    if (r0)
        return r0;
    char *const av[24] = { (char *)"bash", c->activate, c->old, c->release,
        c->manifest_sha, c->new_sha, c->source_id, (char *)"candidate-commit",
        c->new_sha, c->new_sha, (char *)"test-run", (char *)"20", (char *)"6",
        (char *)"20", (char *)"6", (char *)"2", (char *)"2", (char *)"2 4 6",
        (char *)"0", c->node_unit, NULL };
    return srt_run(av, c->home, c->mockbin, out, merge, rc) == 0 ? 0 : 2;
}

int srt_invoke_binding_pub(struct srt_ctx *c, const char *fault,
                           const char *out, int merge, int *rc)
{
    int r0 = srt_fixture_state_pub(c, "", "", fault ? fault : "");
    if (r0)
        return r0;
    char *const av[4] = { (char *)"bash", c->binding_check, c->node_unit,
                          NULL };
    return srt_run(av, c->home, c->mockbin, out, merge, rc) == 0 ? 0 : 2;
}

int srt_reset(struct srt_ctx *c)
{
    int rc = srt_fixture_state_pub(c, "", "", "");
    if (rc)
        return rc;
    char *const av[4] = { c->old, (char *)"reset", c->state_file, NULL };
    int st = 1;
    if (srt_run(av, NULL, NULL, NULL, 0, &st) != 0 || st != 0)
        return 2;
    return 0;
}

int srt_assert_old_selected(struct srt_ctx *c)
{
    if (srt_file_has_exact_line(c->dropin, "prior ship selection") != 1)
        return 1;
    long pid;
    if (srt_read_pid(c->pidfile, &pid))
        return 2;
    char sha[SRT_SHA];
    if (srt_live_exe_sha(pid, sha))
        return 2;
    return strcmp(sha, c->old_sha) == 0 ? 0 : 1;
}

static void srt_cleanup(struct srt_ctx *c)
{
    if (access(c->old, X_OK) != 0)
        return;
    char *const av[4] = { c->old, (char *)"cleanup", c->tmp, NULL };
    int st;
    (void)srt_run(av, NULL, NULL, NULL, 0, &st);
}

int check_ship_remote_transaction_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    static struct srt_ctx c;
    memset(&c, 0, sizeof c);
    int rc = srt_setup(&c);
    if (rc == 0)
        rc = srt_check_all(&c);
    srt_cleanup(&c);
    if (rc == 0)
        printf("%s: PASS (Tor gate precedes transfer; immutable mismatch, "
               "lock, partial stage, reload/restart, precedence, "
               "shadowed-ExecStart refusal, and rollback paths proved)\n",
               k_srt_gate);
    return rc;
}
