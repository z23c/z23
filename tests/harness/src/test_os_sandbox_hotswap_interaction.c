/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Confinement visibility + the confinement/hot-swap filesystem collision.
 *
 * Two things are proven here, both about confinement that is BUILT but
 * DEFAULT OFF (engine/composition/src/boot.c:sr_sandbox_enter / sr_confine_enter):
 *
 * (1) The `confinement` witness (platform/modules/platform/src/os_sandbox_witness.c) is
 *     honest in both directions: it says UNCONFINED when nothing entered, it
 *     distinguishes "nobody requested confinement" from "confinement was
 *     requested and the process is running unconfined anyway", and once a
 *     Landlock domain is live it reports the interface, its ABI, and the
 *     actual grant set the domain was built from.
 *
 * (2) THE COLLISION, which nobody has hit yet because both features are off:
 *     boot scopes the Landlock filesystem grant to the DATA directory, but a
 *     hot-swap module lives under /tmp or <src>/build/hotswap (engine/modules/hotswap/
 *     src/hotswap_loader.c:hotswap_path_is_acceptable). Neither is granted.
 *     So a dev node started with confinement AND swapping enabled fails at
 *     hotswap_activate.c's open(so_path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW) with
 *     a bare EACCES that the current message ("could not pin and hash a
 *     regular module artifact") does not explain.
 *
 *     Landlock hooks file_open, NOT access(2) — so the precheck's
 *     access(so_path, R_OK) still SUCCEEDS and the request sails through
 *     every existing guard before dying at the open. That is exactly why the
 *     failure names nothing today. This suite pins that behaviour and proves
 *     os_sandbox_explain_denied_path() turns it into a typed refusal that
 *     names the restriction and the missing grant.
 *
 * (3) A second latent kill in the same family: a retrofit Landlock join
 *     (os_sandbox_landlock_apply_to_self(), which the health-sweep and
 *     metrics loops call EVERY tick) issues prctl(2) + landlock_restrict_
 *     self(2). Both -confine seccomp allow-sets omit both syscalls, so under
 *     -confine that per-tick call is a SECCOMP_RET_KILL_PROCESS, not a failed
 *     join. The guard must REFUSE the attempt instead of taking the node
 *     down; this proves the refusal, without asserting today's allow-set
 *     membership (a future widening must stay legal).
 *
 * Everything that mutates process state runs in a FRESHLY FORKED child and is
 * judged by its exit status — the same one-way-builder discipline as
 * test_os_sandbox.c. The parent group process is never confined.
 */

#define _GNU_SOURCE

#include "test/test_helpers.h"

#include "platform/os_sandbox.h"
#include "hotswap/hotswap.h"
#include "json/json.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
static int ch_run_child(int (*fn)(void))
{
    pid_t pid = fork();
    if (pid < 0) return -1000;
    if (pid == 0) _exit(fn());
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1001;
    if (WIFSIGNALED(st)) return -WTERMSIG(st);
    return WEXITSTATUS(st);
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
    /* ELF-ish content is irrelevant: the collision fires at open(), long
     * before dlopen ever inspects a byte. */
    bool ok = write(fd, "not-an-elf\n", 11) == 11;
    close(fd);
    return ok;
}

/* Rewrite `buf` in place with its canonical path. Every fixture path is
 * canonicalized up front so the string comparisons below hold on a host where
 * /tmp is a symlink — the recorded grants are canonical by construction. */
static bool canon_path(char *buf, size_t cap)
{
    char real[PATH_MAX];
    if (!realpath(buf, real)) return false;
    size_t n = strlen(real);
    if (n >= cap) return false;
    memcpy(buf, real, n + 1);
    return true;
}

static bool build_fixture(void)
{
    long pid = (long)getpid();
    snprintf(g_datadir, sizeof(g_datadir), "/tmp/zcl_confine_dd_%ld", pid);
    snprintf(g_sibling, sizeof(g_sibling), "%s-dev", g_datadir);
    snprintf(g_modroot, sizeof(g_modroot), "/tmp/zcl_confine_mod_%ld", pid);
    snprintf(g_tmp_modpath, sizeof(g_tmp_modpath),
             "/tmp/zcl_confine_tmpmod_%ld.so", pid);

    char build[200], hs[240];
    snprintf(build, sizeof(build), "%s/build", g_modroot);
    snprintf(hs, sizeof(hs), "%s/build/hotswap", g_modroot);

    if (mkdir(g_datadir, 0700) != 0 && errno != EEXIST) return false;
    if (mkdir(g_sibling, 0700) != 0 && errno != EEXIST) return false;
    if (mkdir(g_modroot, 0700) != 0 && errno != EEXIST) return false;
    if (mkdir(build, 0700) != 0 && errno != EEXIST) return false;
    if (mkdir(hs, 0700) != 0 && errno != EEXIST) return false;

    if (!canon_path(g_datadir, sizeof(g_datadir)) ||
        !canon_path(g_sibling, sizeof(g_sibling)) ||
        !canon_path(g_modroot, sizeof(g_modroot)))
        return false;

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

    /* The ABI is CACHED at build time: re-probing from a confined process is
     * a kill under -confine, so the witness must never need a live probe. */
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

/* The dumper, read from inside a live domain: it must report the grant set
 * and NOT claim to be unconfined. */
static int c_dumper_inside_domain(void)
{
    os_sandbox_note_requested("node_steady_state");
    if (!enter_datadir_only_domain()) return 30;

    struct json_value v;
    json_init(&v);
    if (!confinement_dump_state_json(&v, NULL)) { json_free(&v); return 31; }

    int rc = 0;
    const struct json_value *iface = json_get(&v, "fs_restriction_interface");
    const struct json_value *abi = json_get(&v, "fs_restriction_abi");
    const struct json_value *cnt = json_get(&v, "fs_grant_count");
    const struct json_value *req = json_get(&v, "requested_profile");
    const struct json_value *grants = json_get(&v, "fs_grants");
    const struct json_value *unc = json_get(&v, "unconfined");
    const struct json_value *rbu = json_get(&v, "requested_but_unconfined");

    if (!unc || json_get_bool(unc))                             rc = 38;
    else if (!rbu || json_get_bool(rbu))                        rc = 39;
    else if (!iface || strcmp(json_get_str(iface), "landlock") != 0) rc = 32;
    else if (!abi || json_get_int(abi) < 1)                     rc = 33;
    else if (!cnt || json_get_int(cnt) != 1)                    rc = 34;
    else if (!req || strcmp(json_get_str(req), "node_steady_state") != 0) rc = 35;
    else if (!grants || json_size(grants) != 1)                 rc = 36;
    else {
        const struct json_value *g0 = json_at(grants, 0);
        const struct json_value *path = g0 ? json_get(g0, "path") : NULL;
        if (!path || strcmp(json_get_str(path), g_datadir) != 0) rc = 37;
    }
    json_free(&v);
    return rc;
}

/* ── (2) the confinement / hot-swap collision ──────────────────────────── */

/* Pin the exact shape of the bug: with the datadir-only domain live, a
 * hot-swap module path
 *   - still passes every existing hot-swap precheck (access(2) is not a
 *     Landlock hook, so the guard cannot see the wall), and
 *   - dies at the same open() hotswap_activate.c uses, with EACCES.
 * Both legal module homes (/tmp and .../build/hotswap) are outside the grant,
 * so the collision is not specific to the source tree. */
static int c_hotswap_module_open_is_denied(void)
{
    char why[256] = {0};
    if (!hotswap_path_is_acceptable(g_modpath, why, sizeof(why))) return 40;
    if (!hotswap_path_is_acceptable(g_tmp_modpath, why, sizeof(why))) return 41;

    if (!enter_datadir_only_domain()) return 42;

    /* The precheck STILL passes under confinement — Landlock hooks file_open,
     * not access(2), so nothing before the open can see the wall. Reported,
     * not asserted: if a future kernel starts hooking access(2) the precheck
     * would instead say "file does not exist / unreadable", which names the
     * confinement no better. Either way the collision below stands. */
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

    /* A granted path yields no message, so the call doubles as the predicate
     * at the refusal site without a second branch. */
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

    /* From here on every syscall outside the allow-set kills this child. The
     * witness must be readable (pure atomic loads)... */
    if (os_sandbox_retrofit_join_permitted() != expect_permitted) return 73;

    /* ...and the per-tick retrofit join the health/metrics loops make must
     * return a non-ok instead of issuing the syscall that would kill us. A
     * SIGSYS here surfaces as a negative code in the parent, so this child
     * returning at all is itself the proof. */
    struct zcl_result r = os_sandbox_landlock_apply_to_self();
    if (expect_permitted) {
        /* Widened allow-set: the join is legal, only its outcome is untested
         * here (no domain exists in this child, so it reports unavailable). */
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

    if (!build_fixture()) {
        printf("confinement: FIXTURE SETUP FAILED (%s)\n", strerror(errno));
        tear_down_fixture();
        return 1;
    }

    /* Unconfined baseline — asserted in the PARENT, which stays unconfined
     * for the whole group. This is the state every node runs in today. */
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
        /* Degraded kernel: the collision cannot be demonstrated, but the
         * fail-open contract above already holds. Skip loudly. */
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
