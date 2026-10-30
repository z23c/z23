/* Copyright 2026 Rhett Creeton - Apache License 2.0
 *
 * purpose: the proof phases of gate check_ship_remote_transaction (immutable
 * mismatch, activation lock, partial stage, reload/restart faults, drop-in
 * precedence, shadowed-ExecStart refusal, rollback, legacy and binding
 * paths), in the same order and with the same messages as the shell
 * original. Setup and the entry point live in gate_ship_remote_transaction.c.
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

static const char *const k_srt_workers[] = {
    "z23-package-verify", "z23-package-verify-dev",
    "zclassic23-package-verify", "zclassic23-package-verify-dev",
};
static const char *const k_srt_faults[] = { "reload", "restart" };

static int srt_run_release_check(struct srt_ctx *c, int *rc)
{
    char *const av[8] = { (char *)"bash", c->release_check, c->release,
        c->manifest_sha, c->new_sha, c->new_sha, c->new_sha, NULL };
    return srt_run(av, NULL, NULL, "/dev/null", 1, rc) == 0 ? 0 : 2;
}

static int srt_install_release(const struct srt_ctx *c)
{
    char p[SRT_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/MANIFEST.sha256", c->release),
            sizeof p))
        return 2;
    if (srt_copy_file(c->manifest, p, 0))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/z23", c->release), sizeof p))
        return 2;
    if (srt_copy_file(c->new, p, 1))
        return 2;
    for (size_t i = 0; i < 4; i++) {
        if (ovf(snprintf(p, sizeof p, "%s/%s", c->release, k_srt_workers[i]),
                sizeof p))
            return 2;
        if (srt_copy_file(c->new, p, 1))
            return 2;
    }
    return 0;
}

static int srt_phase_immutable(struct srt_ctx *c)
{
    if (srt_mkdirp(c->release))
        return 2;
    int rc = srt_install_release(c);
    if (rc)
        return rc;
    int st;
    rc = srt_run_release_check(c, &st);
    if (rc)
        return rc;
    if (st != 0) {
        fprintf(stderr, "%s: complete immutable root was refused\n",
                k_srt_gate);
        return 1;
    }
    return 0;
}

static int srt_phase_corrupt_cycle(struct srt_ctx *c, const char *w)
{
    char p[SRT_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/%s", c->release, w), sizeof p))
        return 2;
    if (srt_write_file(p, "corrupt"))
        return 2;
    int st;
    int rc = srt_run_release_check(c, &st);
    if (rc)
        return rc;
    if (st == 0) {
        fprintf(stderr, "%s: immutable root with corrupt %s passed\n",
                k_srt_gate, w);
        return 1;
    }
    char body[64];
    size_t len;
    if (srt_read_file(p, body, sizeof body, &len))
        return 2;
    if (len != 7 || memcmp(body, "corrupt", 7) != 0)
        return 1;
    if (unlink(p) != 0)
        return 2;
    rc = srt_run_release_check(c, &st);
    if (rc)
        return rc;
    if (st == 0) {
        fprintf(stderr, "%s: immutable root missing %s passed\n", k_srt_gate,
                w);
        return 1;
    }
    if (srt_copy_file(c->new, p, 1))
        return 2;
    return 0;
}

static int srt_phase_lock(struct srt_ctx *c)
{
    char conf[SRT_PATH], text[512], lockdir[SRT_PATH];
    if (ovf(snprintf(conf, sizeof conf, "%s/zzzz-z23-release.conf",
                     c->dropin_dir), sizeof conf))
        return 2;
    if (ovf(snprintf(text, sizeof text, "[Service]\nExecStart=\"%s\"\n",
                     c->old), sizeof text))
        return 2;
    if (srt_write_file(conf, text))
        return 2;
    int rc = srt_reset(c);
    if (rc)
        return rc;
    if (ovf(snprintf(lockdir, sizeof lockdir, "%s/.cache/z23/ship-activation.lock",
                     c->home), sizeof lockdir))
        return 2;
    if (srt_mkdirp(lockdir))
        return 2;
    int st;
    rc = srt_invoke_activate(c, NULL, "/dev/null", 1, &st);
    if (rc)
        return rc;
    if (st == 0) {
        fprintf(stderr, "%s: concurrent activation lock passed\n", k_srt_gate);
        return 1;
    }
    if (!lintc_is_dir(lockdir))
        return 1;
    rc = srt_assert_old_selected(c);
    if (rc)
        return rc;
    if (rmdir(lockdir) != 0)
        return 1;
    return 0;
}

static int srt_phase_corrupt_worker(struct srt_ctx *c, const char *w,
                                    const char *msg)
{
    int rc = srt_reset(c);
    if (rc)
        return rc;
    char p[SRT_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/%s", c->incoming, w), sizeof p))
        return 2;
    if (srt_write_file(p, "corrupt"))
        return 2;
    int st;
    rc = srt_invoke_activate(c, NULL, "/dev/null", 1, &st);
    if (rc)
        return rc;
    if (st == 0) {
        fprintf(stderr, "%s: %s\n", k_srt_gate, msg);
        return 1;
    }
    return srt_assert_old_selected(c);
}

static int srt_phase_faults(struct srt_ctx *c, const char *msgfmt)
{
    for (size_t i = 0; i < 2; i++) {
        int rc = srt_reset(c);
        if (rc)
            return rc;
        int st;
        rc = srt_invoke_activate(c, k_srt_faults[i], "/dev/null", 1, &st);
        if (rc)
            return rc;
        if (st == 0) {
            char msg[256];
            if (ovf(snprintf(msg, sizeof msg, msgfmt, k_srt_faults[i]),
                    sizeof msg))
                return 2;
            fprintf(stderr, "%s: %s\n", k_srt_gate, msg);
            return 1;
        }
        rc = srt_assert_old_selected(c);
        if (rc)
            return rc;
    }
    return 0;
}

static void srt_print_first_lines(const char *body, int max)
{
    int n = 0;
    const char *p = body;
    while (*p && n < max) {
        const char *e = strchr(p, '\n');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        fprintf(stderr, "%.*s\n", (int)l, p);
        if (!e)
            break;
        p = e + 1;
        n++;
    }
}

static int srt_shadow_write(const struct srt_ctx *c, char shadow[SRT_PATH])
{
    char text[512];
    if (ovf(snprintf(shadow, SRT_PATH, "%s/zzzzzz-node-first.conf",
                     c->dropin_dir), SRT_PATH))
        return 2;
    if (ovf(snprintf(text, sizeof text,
                     "[Service]\nExecStart=\nExecStart=\"%s\"\n", c->old),
            sizeof text))
        return 2;
    return srt_write_file(shadow, text) ? 2 : 0;
}

static int srt_shadow_check_output(const char *guard_out)
{
    static char body[SRT_OUT];
    size_t len;
    if (srt_read_file(guard_out, body, sizeof body, &len))
        return 2;
    if (!strstr(body,
                "REFUSE: the unit will not run the release this ship installed")) {
        fprintf(stderr, "%s: shadow refusal message is missing\n", k_srt_gate);
        srt_print_first_lines(body, 40);
        return 1;
    }
    if (!strstr(body, "zzzzzz-node-first.conf")) {
        fprintf(stderr, "%s: refusal did not name the shadowing drop-in\n",
                k_srt_gate);
        return 1;
    }
    return 0;
}

static int srt_phase_shadow(struct srt_ctx *c)
{
    char shadow[SRT_PATH], guard_out[SRT_PATH];
    int rc = srt_shadow_write(c, shadow);
    if (!rc)
        rc = srt_reset(c);
    if (rc)
        return rc;
    long before_pid;
    if (srt_read_pid(c->pidfile, &before_pid))
        return 2;
    if (ovf(snprintf(guard_out, sizeof guard_out, "%s/guard.out", c->tmp),
            sizeof guard_out))
        return 2;
    int st;
    rc = srt_invoke_activate(c, NULL, guard_out, 1, &st);
    if (rc)
        return rc;
    if (st == 0) {
        fprintf(stderr, "%s: shadowed ExecStart passed activation\n",
                k_srt_gate);
        return 1;
    }
    rc = srt_shadow_check_output(guard_out);
    if (!rc)
        rc = srt_assert_old_selected(c);
    if (rc)
        return rc;
    long pid;
    if (srt_read_pid(c->pidfile, &pid))
        return 2;
    if (pid != before_pid) {
        fprintf(stderr, "%s: shadow refusal restarted the service\n",
                k_srt_gate);
        return 1;
    }
    return unlink(shadow) != 0 ? 2 : 0;
}

static int srt_sha_of_release_file(const struct srt_ctx *c, const char *name,
                                   char sha[SRT_SHA])
{
    char p[SRT_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/%s", c->release, name), sizeof p))
        return 2;
    return srt_sha256_file(p, sha) == 0 ? 0 : 2;
}

static int srt_release_workers_new(const struct srt_ctx *c)
{
    static const char *const names[] = { "z23-package-verify",
                                         "zclassic23-package-verify" };
    char sha[SRT_SHA];
    for (size_t i = 0; i < 2; i++) {
        int rc = srt_sha_of_release_file(c, names[i], sha);
        if (rc == 0 && strcmp(sha, c->new_sha) != 0)
            rc = 1;
        if (rc)
            return rc;
    }
    return 0;
}

static int srt_phase_select(struct srt_ctx *c)
{
    int rc = srt_reset(c);
    if (rc)
        return rc;
    int st;
    rc = srt_invoke_activate(c, NULL, "/dev/null", 0, &st);
    if (rc)
        return rc;
    if (st != 0)
        return 1;
    long pid;
    if (srt_read_pid(c->pidfile, &pid))
        return 2;
    char sha[SRT_SHA];
    if (srt_live_exe_sha(pid, sha))
        return 2;
    if (strcmp(sha, c->new_sha) != 0)
        return 1;
    rc = srt_release_workers_new(c);
    if (rc)
        return rc;
    char needle[2 * SRT_PATH];
    if (ovf(snprintf(needle, sizeof needle, "ExecStart=\"%s/z23\"", c->release),
            sizeof needle))
        return 2;
    int hit = srt_file_contains(c->dropin, needle);
    return hit == 1 ? 0 : (hit < 0 ? 2 : 1);
}

static int srt_run_rollback(struct srt_ctx *c, const char *out, int merge,
                            int *st)
{
    char *const av[12] = { (char *)"bash", c->rollback, c->old,
        (char *)"test-run", c->old_sha, (char *)"20", (char *)"6",
        (char *)"2", (char *)"2", (char *)"2 4 6", c->node_unit, NULL };
    return srt_run(av, c->home, c->mockbin, out, merge, st) == 0 ? 0 : 2;
}

static int srt_phase_rollback(struct srt_ctx *c)
{
    int st;
    int rc = srt_run_rollback(c, "/dev/null", 0, &st);
    if (rc)
        return rc;
    if (st != 0)
        return 1;
    if (srt_file_has_exact_line(c->dropin, "prior ship selection") != 1)
        return 1;
    long pid;
    if (srt_read_pid(c->pidfile, &pid))
        return 2;
    char sha[SRT_SHA];
    if (srt_live_exe_sha(pid, sha))
        return 2;
    if (strcmp(sha, c->old_sha) != 0)
        return 1;
    rc = srt_sha_of_release_file(c, "z23", sha);
    if (rc)
        return rc;
    return strcmp(sha, c->new_sha) == 0 ? 0 : 1;
}

static int srt_phase_fallback(struct srt_ctx *c)
{
    int rc = srt_reset(c);
    if (rc)
        return rc;
    int st;
    rc = srt_invoke_activate(c, NULL, "/dev/null", 0, &st);
    if (rc)
        return rc;
    if (st != 0)
        return 1;
    rc = srt_fixture_state_pub(c, "", "restart", "");
    if (rc)
        return rc;
    rc = srt_run_rollback(c, "/dev/null", 1, &st);
    if (rc)
        return rc;
    if (st == 0) {
        fprintf(stderr, "%s: fallback restart failure passed\n", k_srt_gate);
        return 1;
    }
    char sha[SRT_SHA];
    rc = srt_sha_of_release_file(c, "z23", sha);
    if (rc)
        return rc;
    return strcmp(sha, c->new_sha) == 0 ? 0 : 1;
}

/* One line in tools/ship.sh must come before another. Each needle carries
 * the srt_grep_lineno prefix/last switches its grep used. */
struct srt_needle {
    const char *text;
    int prefix, last;
};

static int srt_phase_order(const struct srt_needle *before,
                           const struct srt_needle *after)
{
    long a, b;
    if (srt_grep_lineno("tools/ship.sh", before->text, before->prefix,
                        before->last, &a) != 1)
        return 2;
    if (srt_grep_lineno("tools/ship.sh", after->text, after->prefix,
                        after->last, &b) != 1)
        return 2;
    return a < b ? 0 : 1;
}

static int srt_phase_tor_order(void)
{
    static const struct srt_needle tor = {
        "ship_candidate_has_real_tor \"$CANDIDATE\"", 0, 1 };
    static const struct srt_needle dep = { "deploy_remote()", 1, 0 };
    return srt_phase_order(&tor, &dep);
}

static int srt_all_lines_unit(const char *body, const char *unit)
{
    size_t ul = strlen(unit);
    const char *p = body;
    while (*p) {
        const char *e = strchr(p, '\n');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l != ul || strncmp(p, unit, l) != 0)
            return 0;
        if (!e)
            break;
        p = e + 1;
        if (!*p)
            break;
    }
    return 1;
}

static int srt_legacy_select(struct srt_ctx *c, const char *restarts)
{
    int rc = srt_reset(c);
    if (rc)
        return rc;
    int st;
    rc = srt_invoke_activate(c, NULL, "/dev/null", 0, &st);
    if (rc)
        return rc;
    if (st != 0)
        return 1;
    long pid;
    if (srt_read_pid(c->pidfile, &pid))
        return 2;
    char sha[SRT_SHA];
    if (srt_live_exe_sha(pid, sha))
        return 2;
    if (strcmp(sha, c->new_sha) != 0)
        return 1;
    char needle[2 * SRT_PATH];
    if (ovf(snprintf(needle, sizeof needle,
                     "ExecStart=\"%s/z23\" \"-fixture-node\"", c->release),
            sizeof needle))
        return 2;
    int hit = srt_file_contains(c->dropin, needle);
    if (hit != 1)
        return hit < 0 ? 2 : 1;
    static char body[SRT_OUT];
    size_t len;
    if (srt_read_file(restarts, body, sizeof body, &len))
        return 2;
    if (len == 0)
        return 1;
    return srt_all_lines_unit(body, c->node_unit) ? 0 : 1;
}

static int srt_phase_legacy(struct srt_ctx *c)
{
    char def_dropin[SRT_PATH], def_sha[SRT_SHA], restarts[SRT_PATH];
    if (strlen(c->dropin) >= sizeof def_dropin)
        return 2;
    strcpy(def_dropin, c->dropin);
    if (srt_sha256_file(def_dropin, def_sha))
        return 2;
    if (ovf(snprintf(c->node_unit, sizeof c->node_unit, "zclassic23.service"),
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
    if (srt_mkdirp(c->dropin_dir))
        return 2;
    if (ovf(snprintf(restarts, sizeof restarts, "%s/service.pid.restarts",
                     c->tmp), sizeof restarts))
        return 2;
    if (srt_write_file(restarts, ""))
        return 2;
    int rc = srt_phase_faults(c, "legacy survived %s fault");
    if (rc)
        return rc;
    rc = srt_legacy_select(c, restarts);
    if (rc)
        return rc;
    char sha[SRT_SHA];
    if (srt_sha256_file(def_dropin, sha))
        return 2;
    return strcmp(sha, def_sha) == 0 ? 0 : 1;
}

static int srt_binding_faults(struct srt_ctx *c, const char *restarts)
{
    static const char *const faults[2] = { "both", "missing" };
    for (size_t i = 0; i < 2; i++) {
        long pid0;
        if (srt_read_pid(c->pidfile, &pid0))
            return 2;
        static char body[SRT_OUT];
        size_t len;
        if (srt_read_file(restarts, body, sizeof body, &len))
            return 2;
        size_t before = srt_count_lines(body, len);
        int st;
        int rc = srt_invoke_binding_pub(c, faults[i], "/dev/null", 1, &st);
        if (rc)
            return rc;
        if (st == 0) {
            fprintf(stderr, "%s: %s binding passed\n", k_srt_gate,
                    faults[i]);
            return 1;
        }
        long pid;
        if (srt_read_pid(c->pidfile, &pid))
            return 2;
        if (pid != pid0)
            return 1;
        if (srt_read_file(restarts, body, sizeof body, &len))
            return 2;
        if (srt_count_lines(body, len) != before)
            return 1;
    }
    return 0;
}

static int srt_stop_twice(struct srt_ctx *c)
{
    for (int i = 0; i < 2; i++) {
        char *const av[4] = { c->old, (char *)"stop", c->state_file, NULL };
        int st = 1;
        if (srt_run(av, NULL, NULL, NULL, 0, &st) != 0 || st != 0)
            return 2;
    }
    return 0;
}

static int srt_phase_binding(struct srt_ctx *c)
{
    int st;
    int rc = srt_invoke_binding_pub(c, NULL, NULL, 0, &st);
    if (rc)
        return rc;
    if (st != 0)
        return 1;
    char restarts[SRT_PATH];
    if (ovf(snprintf(restarts, sizeof restarts, "%s/service.pid.restarts",
                     c->tmp), sizeof restarts))
        return 2;
    rc = srt_binding_faults(c, restarts);
    if (rc)
        return rc;
    return srt_stop_twice(c);
}

static int srt_phase_binding_order(void)
{
    static const struct srt_needle b = {
        "ship_remote_binding_check \"$host\" ||", 0, 0 };
    static const struct srt_needle s = {
        "ship_remote_rollout stage_remote deploy_remote", 0, 0 };
    return srt_phase_order(&b, &s);
}

int srt_check_all(struct srt_ctx *c)
{
    int rc = srt_phase_immutable(c);
    for (size_t i = 0; !rc && i < 4; i++)
        rc = srt_phase_corrupt_cycle(c, k_srt_workers[i]);
    if (!rc)
        rc = srt_phase_lock(c);
    if (!rc)
        rc = srt_phase_corrupt_worker(c, "z23-package-verify-dev",
                                      "corrupt worker passed");
    if (!rc)
        rc = srt_phase_corrupt_worker(c, "zclassic23-package-verify",
                                      "corrupt legacy-name worker passed");
    if (!rc)
        rc = srt_phase_faults(c, "activation survived %s fault");
    if (!rc)
        rc = srt_phase_shadow(c);
    if (!rc)
        rc = srt_phase_select(c);
    if (!rc)
        rc = srt_phase_rollback(c);
    if (!rc)
        rc = srt_phase_fallback(c);
    if (!rc)
        rc = srt_phase_tor_order();
    if (!rc)
        rc = srt_phase_legacy(c);
    if (!rc)
        rc = srt_phase_binding(c);
    if (!rc)
        rc = srt_phase_binding_order();
    return rc;
}
