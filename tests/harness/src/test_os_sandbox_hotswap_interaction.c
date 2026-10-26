/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Confinement witness honesty and the confinement/hot-swap collision
 * (confinement is built but default off; engine/composition/src/boot.c).
 *
 * (1) The `confinement` witness reports UNCONFINED when nothing entered,
 *     distinguishes "not requested" from "requested but unconfined", and in
 *     a live Landlock domain reports the interface, ABI and grant set.
 * (2) Boot grants only the DATA directory, but hot-swap modules live under
 *     /tmp or <src>/build/hotswap, so open() fails with a bare EACCES
 *     (Landlock hooks file_open, not access(2), so prechecks pass).
 *     os_sandbox_explain_denied_path() turns that into a typed refusal.
 * (3) A retrofit Landlock join issues prctl(2) + landlock_restrict_self(2),
 *     which both -confine seccomp allow-sets omit; the guard must refuse
 *     the attempt instead of being killed.
 *
 * State-mutating checks run in a freshly forked child judged by exit status;
 * the parent group process is never confined. */

#define _GNU_SOURCE

#include "test/test_helpers.h"

#include "platform/os_sandbox.h"
#include "hotswap/hotswap.h"
#include "json/json.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif
#include <unistd.h>

#if !defined(__linux__)

int test_os_sandbox_hotswap_interaction(void)
{
    printf("\n=== confinement/hot-swap platform availability ===\n");
    printf("confinement: Landlock/seccomp interaction is not applicable "
           "on this host\n");
    return os_sandbox_landlock_abi() < 1 &&
           !os_sandbox_seccomp_supported() ? 0 : 1;
}

#else

static int failures;

#define CH_CHECK(name, expr) do { \
    printf("confinement: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Run fn() in a forked child; returns its exit code, or the negated
 * terminating signal so a SIGSYS kill is distinguishable from a return. */
static unsigned ch_wait_interruptions;
static pid_t (*ch_wait_child)(pid_t, int *, int) = waitpid;

static pid_t ch_wait_eintr_once(pid_t pid, int *st, int options)
{
    (void)pid;
    (void)st;
    (void)options;
    ch_wait_child = waitpid;
    errno = EINTR;
    return -1;
}

static int ch_run_child(int (*fn)(void))
{
    pid_t pid = fork();
    if (pid < 0) return -1000;
    if (pid == 0) _exit(fn());
    int st = 0;
    pid_t waited;
    do {
        waited = ch_wait_child(pid, &st, 0);
        if (waited < 0 && errno == EINTR) ch_wait_interruptions++;
    } while (waited < 0 && errno == EINTR);
    if (waited != pid) return -1001;
    if (WIFSIGNALED(st)) return -WTERMSIG(st);
    return WEXITSTATUS(st);
}

static int c_exit_42(void)
{
    return 42;
}

static int c_interrupted_wait_reaps_child(void)
{
    /* This deadline also bounds orphan cleanup on the restored defect. */
    if (signal(SIGALRM, SIG_DFL) == SIG_ERR) return 86;
    alarm(5);
    ch_wait_interruptions = 0;
    ch_wait_child = ch_wait_eintr_once;
    int result = ch_run_child(c_exit_42);
    ch_wait_child = waitpid;
    int st = 0;
    errno = 0;
    pid_t leftover = waitpid(-1, &st, WNOHANG);
    bool reaped = leftover == -1 && errno == ECHILD;
    if (leftover == 0) {
        /* Baseline returns while its child lives: settle that ownership
         * before reporting the original result, without hiding failure. */
        do {
            leftover = waitpid(-1, &st, 0);
        } while (leftover < 0 && errno == EINTR);
        if (leftover < 0) return 84;
    }
    alarm(0);
    return result == 42 && ch_wait_interruptions == 1 &&
           reaped ? 0 : 85;
}

/* ── fixture paths (built by the parent, read by the children) ─────────── */

static char g_datadir[160];      /* the ONLY granted tree, mirroring boot */
static char g_modroot[160];      /* the hot-swap tree, deliberately outside */
static char g_modpath[256];      /* <modroot>/build/hotswap/mod.so         */
static char g_tmp_modpath[256];  /* /tmp/<...>.so — the other legal home   */
static char g_sibling[200];      /* <datadir>-dev — the prefix-match trap  */

static bool touch_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    /* Content is irrelevant: the collision fires at open(). */
    bool ok = write(fd, "not-an-elf\n", 11) == 11;
    close(fd);
    return ok;
}

/* Rewrite `buf` in place with its canonical path (so /tmp symlinks match
 * the recorded grants). */
static bool canon_path(char *buf, size_t cap)
{
    char real[PATH_MAX];
    if (!realpath(buf, real)) return false;
    size_t n = strlen(real);
    if (n >= cap) return false;
    memcpy(buf, real, n + 1);
    return true;
}

/* Write the pid-derived fixture paths into the path globals. */
static void fixture_compose_paths(void)
{
    long pid = (long)getpid();
    snprintf(g_datadir, sizeof(g_datadir), "/tmp/zcl_confine_dd_%ld", pid);
    snprintf(g_sibling, sizeof(g_sibling), "%s-dev", g_datadir);
    snprintf(g_modroot, sizeof(g_modroot), "/tmp/zcl_confine_mod_%ld", pid);
    snprintf(g_tmp_modpath, sizeof(g_tmp_modpath),
             "/tmp/zcl_confine_tmpmod_%ld.so", pid);
}

/* mkdir() the fixture tree in dependency order, tolerating EEXIST;
 * returns 0 on success, 1 on the first directory that cannot be made. */
static int fixture_create_directories(void)
{
    char build[200], hs[240];
    snprintf(build, sizeof(build), "%s/build", g_modroot);
    snprintf(hs, sizeof(hs), "%s/build/hotswap", g_modroot);

    const char *dirs[] = { g_datadir, g_sibling, g_modroot, build, hs };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
        if (mkdir(dirs[i], 0700) != 0 && errno != EEXIST) return 1;
    return 0;
}

/* Rewrite the three root globals to their canonical paths (the module
 * paths are derived afterwards, from the canonical g_modroot); returns
 * the combined canon_path() result. */
static bool fixture_canonicalize_roots(void)
{
    return canon_path(g_datadir, sizeof(g_datadir)) &&
           canon_path(g_sibling, sizeof(g_sibling)) &&
           canon_path(g_modroot, sizeof(g_modroot));
}

static bool build_fixture(void)
{
    fixture_compose_paths();
    if (fixture_create_directories() != 0) return false;
    if (!fixture_canonicalize_roots()) return false;

    snprintf(g_modpath, sizeof(g_modpath), "%s/build/hotswap/mod.so", g_modroot);
    if (!touch_file(g_modpath) || !touch_file(g_tmp_modpath))
        return false;
    return canon_path(g_modpath, sizeof(g_modpath)) &&
           canon_path(g_tmp_modpath, sizeof(g_tmp_modpath));
}

static void tear_down_fixture(void)
{
    unlink(g_tmp_modpath);
    test_rm_rf_recursive(g_modroot);
    test_rm_rf_recursive(g_sibling);
    test_rm_rf_recursive(g_datadir);
}

/* Enter a Landlock domain granting rw on the datadir only — the shape
 * engine/composition/src/boot.c:sandbox_build_fs_rules produces for a node. */
static bool enter_datadir_only_domain(void)
{
    struct os_sandbox_path_rule rules[] = {{ .path = g_datadir, .allow_read = true, .allow_write = true }};
    if (!os_sandbox_no_new_privs()) return false;
    return os_sandbox_landlock_restrict(rules, 1).ok;
}

/* ── (1) the witness is honest about the grant set ─────────────────────── */

static int c_witness_records_grants(void)
{
    os_sandbox_note_requested("node_confine");
    if (!enter_datadir_only_domain()) return 10;

    if (os_sandbox_fs_grant_count() != 1) return 11;
    bool r = false, w = false;
    const char *p = os_sandbox_fs_grant_at(0, &r, &w);
    if (!p || strcmp(p, g_datadir) != 0) return 12;
    if (!r || !w) return 13;
    if (os_sandbox_fs_grant_at(1, NULL, NULL) != NULL) return 14;

    /* The ABI is cached at build time: a live probe under -confine is a kill. */
    if (os_sandbox_landlock_abi_cached() < 1) return 15;

    /* Inside the grant: allowed. Outside: provably denied. */
    char inside[256];
    snprintf(inside, sizeof(inside), "%s/node.db", g_datadir);
    if (!os_sandbox_path_is_granted(inside, true)) return 16;
    if (os_sandbox_path_is_granted("/etc/hostname", false)) return 17;

    /* Prefix-match trap: a grant of <dd> must not cover <dd>-dev. */
    char sib[256];
    snprintf(sib, sizeof(sib), "%s/x", g_sibling);
    if (os_sandbox_path_is_granted(sib, false)) return 18;

    /* Fail-open on anything unprovable — a NULL or relative path is not this
     * module's business and must never produce a refusal. */
    if (!os_sandbox_path_is_granted(NULL, false)) return 19;
    if (!os_sandbox_path_is_granted("relative/path", false)) return 20;
    return 0;
}

/* Both "not confined" flags must be present and false; returns the first
 * breach's code (38/39) or 0. */
static int dumper_check_unconfined_flags(const struct json_value *doc)
{
    const struct json_value *unc = json_get(doc, "unconfined");
    const struct json_value *rbu = json_get(doc, "requested_but_unconfined");
    if (!unc || json_get_bool(unc)) return 38;
    if (!rbu || json_get_bool(rbu)) return 39;
    return 0;
}

/* The interface/abi/count/profile scalars; returns the first mismatch's
 * code (32-35) or 0. */
static int dumper_check_restriction_scalars(const struct json_value *doc)
{
    const struct json_value *iface = json_get(doc, "fs_restriction_interface");
    const struct json_value *abi = json_get(doc, "fs_restriction_abi");
    const struct json_value *cnt = json_get(doc, "fs_grant_count");
    const struct json_value *req = json_get(doc, "requested_profile");
    if (!iface || strcmp(json_get_str(iface), "landlock") != 0) return 32;
    if (!abi || json_get_int(abi) < 1) return 33;
    if (!cnt || json_get_int(cnt) != 1) return 34;
    if (!req || strcmp(json_get_str(req), "node_steady_state") != 0) return 35;
    return 0;
}

/* The one recorded grant must be the datadir itself; returns 36/37 or 0. */
static int dumper_check_grant_entry(const struct json_value *doc)
{
    const struct json_value *grants = json_get(doc, "fs_grants");
    if (!grants || json_size(grants) != 1) return 36;
    const struct json_value *g0 = json_at(grants, 0);
    const struct json_value *path = g0 ? json_get(g0, "path") : NULL;
    if (!path || strcmp(json_get_str(path), g_datadir) != 0) return 37;
    return 0;
}

/* The dumper, read from inside a live domain: it must report the grant set
 * and NOT claim to be unconfined. */
static int c_dumper_inside_domain(void)
{
    os_sandbox_note_requested("node_steady_state");
    if (!enter_datadir_only_domain()) return 30;

    struct json_value v;
    json_init(&v);
    if (!confinement_dump_state_json(&v, NULL)) { json_free(&v); return 31; }

    /* Same checks, same order: the first failing one still wins. */
    int rc = dumper_check_unconfined_flags(&v);
    if (rc == 0) rc = dumper_check_restriction_scalars(&v);
    if (rc == 0) rc = dumper_check_grant_entry(&v);
    json_free(&v);
    return rc;
}

/* ── (2) the confinement / hot-swap collision ──────────────────────────── */

/* With the datadir-only domain live, a hot-swap module path passes every
 * precheck (access(2) is not a Landlock hook) and dies at the
 * hotswap_activate.c open() with EACCES. Both legal module homes lie outside
 * the grant. */
static int c_hotswap_module_open_is_denied(void)
{
    char why[256] = {0};
    if (!hotswap_path_is_acceptable(g_modpath, why, sizeof(why))) return 40;
    if (!hotswap_path_is_acceptable(g_tmp_modpath, why, sizeof(why))) return 41;

    if (!enter_datadir_only_domain()) return 42;

    /* The precheck still passes: Landlock hooks file_open, not access(2).
     * Reported, not asserted. */
    why[0] = '\0';
    bool precheck_ok = hotswap_path_is_acceptable(g_modpath, why, sizeof(why));
    printf("confinement: [obs] precheck under confinement: %s (%s)\n",
           precheck_ok ? "PASSES — blind to the restriction" : "rejects",
           why[0] ? why : "no reason given");

    /* The real open, byte-identical to hotswap_activate.c, is denied. */
    int fd = open(g_modpath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) { close(fd); return 44; }
    if (errno != EACCES) return 45;

    int fd2 = open(g_tmp_modpath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd2 >= 0) { close(fd2); return 46; }
    if (errno != EACCES) return 47;
    return 0;
}

/* The diagnosis the refusal needs: predicate false + a message that names the
 * restriction interface, the profile, the offending path, and the grants. */
static int c_refusal_message_names_the_wall(void)
{
    char why[512];
    /* Before any domain: nothing to explain (fail-open, empty message). */
    if (os_sandbox_explain_denied_path(g_modpath, false, why, sizeof(why)) != 0)
        return 50;
    if (why[0] != '\0') return 51;

    if (!enter_datadir_only_domain()) return 52;

    if (os_sandbox_path_is_granted(g_modpath, false)) return 53;
    size_t n = os_sandbox_explain_denied_path(g_modpath, false, why, sizeof(why));
    if (n == 0 || n != strlen(why)) return 54;
    if (!strstr(why, "Landlock")) return 55;
    if (!strstr(why, g_modpath)) return 56;
    if (!strstr(why, g_datadir)) return 57;   /* names the grant that exists */
    if (!strstr(why, "confinement")) return 58;

    /* A granted path yields no message (doubles as the predicate). */
    char inside[256];
    snprintf(inside, sizeof(inside), "%s/node.db", g_datadir);
    if (os_sandbox_explain_denied_path(inside, true, why, sizeof(why)) != 0)
        return 59;

    /* Bounded output: a tiny buffer must truncate, never overflow. */
    char tiny[24];
    size_t t = os_sandbox_explain_denied_path(g_modpath, false, tiny, sizeof(tiny));
    if (t >= sizeof(tiny)) return 60;
    return 0;
}

/* ── (3) the retrofit join must refuse, not die ────────────────────────── */

static int c_retrofit_join_refuses_under_allowlist(void)
{
    size_t n = 0;
    const int *allow = os_sandbox_node_confine_allowed_syscalls(&n);
    if (!allow || n == 0) return 70;

    bool has_prctl = false, has_restrict = false;
    for (size_t i = 0; i < n; i++) {
        if (allow[i] == __NR_prctl) has_prctl = true;
#ifdef __NR_landlock_restrict_self
        if (allow[i] == __NR_landlock_restrict_self) has_restrict = true;
#endif
    }
    const bool expect_permitted = has_prctl && has_restrict;

    if (!os_sandbox_no_new_privs()) return 71;
    if (!os_sandbox_seccomp_allow(allow, n).ok) return 72;

    /* Every syscall outside the allow-set kills this child; the witness
     * must stay readable (pure atomic loads)... */
    if (os_sandbox_retrofit_join_permitted() != expect_permitted) return 73;

    /* The per-tick retrofit join must return non-ok rather than issue the
     * killing syscall; returning at all is the proof. */
    struct zcl_result r = os_sandbox_landlock_apply_to_self();
    if (expect_permitted) {
        /* Widened allow-set: the join is legal (no domain here: unavailable). */
        if (r.ok) return 74;
    } else {
        if (r.ok) return 75;
        if (r.code != OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE) return 76;
    }
    return 0;
}

/* ── entry point ──────────────────────────────────────────────────────── */

int test_os_sandbox_hotswap_interaction(void)
{
    failures = 0;
    printf("=== confinement visibility + hot-swap interaction ===\n");

    CH_CHECK("interrupted child wait returns 42 and leaves no child",
             ch_run_child(c_interrupted_wait_reaps_child) == 0);

    if (!build_fixture()) {
        printf("confinement: FIXTURE SETUP FAILED (%s)\n", strerror(errno));
        tear_down_fixture();
        return 1;
    }

    /* Unconfined baseline, asserted in the parent (never confined). */
    CH_CHECK("unconfined process reports unconfined", os_sandbox_unconfined());
    CH_CHECK("no confinement requested -> empty requested_profile",
             os_sandbox_requested_profile() != NULL &&
             os_sandbox_requested_profile()[0] == '\0');
    CH_CHECK("no domain -> no grants recorded", os_sandbox_fs_grant_count() == 0);
    CH_CHECK("no domain -> cached ABI is -1",
             os_sandbox_landlock_abi_cached() == -1);
    CH_CHECK("unconfined -> every path is granted (fail-open)",
             os_sandbox_path_is_granted(g_modpath, true) &&
             os_sandbox_path_is_granted("/etc/shadow", true));
    CH_CHECK("unconfined -> retrofit join is permitted",
             os_sandbox_retrofit_join_permitted());

    {
        struct json_value v;
        json_init(&v);
        bool ok = confinement_dump_state_json(&v, NULL);
        const struct json_value *unc = ok ? json_get(&v, "unconfined") : NULL;
        const struct json_value *rbu =
            ok ? json_get(&v, "requested_but_unconfined") : NULL;
        const struct json_value *filt =
            ok ? json_get(&v, "syscall_filter_install") : NULL;
        CH_CHECK("dumper: unconfined=true, requested_but_unconfined=false, "
                 "filter=none",
                 ok && unc && json_get_bool(unc) && rbu &&
                 !json_get_bool(rbu) && filt &&
                 strcmp(json_get_str(filt), "none") == 0);
        json_free(&v);
    }

    int abi = os_sandbox_landlock_abi();
    if (abi < 1) {
        /* Degraded kernel: skip loudly. */
        printf("confinement: SKIP (Landlock unavailable, abi=%d) — "
               "fail-open contract still covered above\n", abi);
        tear_down_fixture();
        printf("=== confinement tests done: %d failure(s) ===\n", failures);
        return failures;
    }

    CH_CHECK("witness records the grant set + rejects sibling prefixes",
             ch_run_child(c_witness_records_grants) == 0);
    CH_CHECK("dumper inside a live domain reports interface/abi/grants",
             ch_run_child(c_dumper_inside_domain) == 0);
    CH_CHECK("COLLISION: hot-swap module open is EACCES under a datadir-only "
             "grant, and the precheck cannot see it",
             ch_run_child(c_hotswap_module_open_is_denied) == 0);
    CH_CHECK("refusal message names the restriction, the path, and the grant",
             ch_run_child(c_refusal_message_names_the_wall) == 0);
    CH_CHECK("retrofit join under the -confine allow-list refuses instead of "
             "being SIGSYS-killed",
             ch_run_child(c_retrofit_join_refuses_under_allowlist) == 0);

    tear_down_fixture();
    printf("=== confinement tests done: %d failure(s) ===\n", failures);
    return failures;
}

#endif
