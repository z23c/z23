/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Boot confinement profile and filesystem grants. */
#include "boot_cutover_startup_internal.h"
#include "config/boot.h"
#include "platform/os_sandbox.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

static void sandbox_add_home_dir_rule(struct os_sandbox_path_rule *rules, size_t cap, size_t *n,
                                      char scratch[][PATH_MAX], size_t scratch_cap, size_t *s,
                                      const char *home, const char *subdir, bool allow_write)
{
    if (!(home && home[0] && *n < cap && *s < scratch_cap)) return;
    snprintf(scratch[*s], PATH_MAX, "%s/%s", home, subdir);
    struct stat st;
    if (stat(scratch[*s], &st) == 0 && S_ISDIR(st.st_mode)) {
        rules[(*n)++] = (struct os_sandbox_path_rule){
            .path = scratch[*s], .allow_read = true, .allow_write = allow_write };
        (*s)++;
    }
}
/* Late confinement: enter the os_sandbox node steady-state profile once every
 * thread is spawned and every late fd is open (SERVICES_RUNNING, highest
 * `order` — last record before READY). No-op unless -sandbox=steady.
 * fs grants: the datadir tree (rw, covers <datadir>/ssl + SQLite WAL/shm/tmp),
 * the agent-test status dir when present, and a read-only OS_SANDBOX_PROC_
 * SELF_STATUS_PATH grant (metrics RSS — see os_sandbox_landlock_apply_to_self
 * in platform/os_sandbox.h for the full Landlock-retrofit design/scope note).
 * Fail-closed: an applicable-but-failed confinement request FATALs boot
 * rather than run unconfined. Thread coverage (`dumpstate sandbox`): seccomp
 * installs via TSYNC (every thread, atomically); Landlock has no TSYNC
 * equivalent, so os_sandbox_landlock_apply_to_self() is the retrofit join an
 * already-running thread calls from its own loop — wired into the
 * health-sweep and metrics loops today. Deliberately NOT wired into the
 * supervisor dispatch thread (platform/modules/util/src/supervisor.c): that one thread
 * runs EVERY registered supervisor child's on_tick synchronously, so
 * confining it would confine every dispatched callback across every domain,
 * not just an audited loop — it stays the documented Landlock-unconfined
 * (still seccomp-confined) residual alongside file_service/
 * wallet_backup_service/disk_monitor/event_async. */
/* Build the shared Landlock fs-grant set for the node confinement profiles: rw
 * under the datadir (covers <datadir>/ssl + SQLite WAL/shm/tmp), rw under the
 * agent-test status dir when present, and a read-only self-status grant. Returns
 * the count written into `rules` (capacity >= 3). `extra_ro` toggles the
 * extra read-only paths the confined node opens post-boot (Sapling params dir,
 * /etc/resolv.conf) — enabled for -confine, which uses a strict seccomp
 * allow-list and therefore benefits from the fuller path set. */
static size_t sandbox_build_fs_rules(const char *datadir,
                                     struct os_sandbox_path_rule *rules,
                                     size_t cap, bool extra_ro,
                                     char scratch[][PATH_MAX], size_t scratch_cap)
{
    size_t n = 0;
    size_t s = 0;
    if (cap == 0) return 0;
    rules[n++] = (struct os_sandbox_path_rule){
        .path = datadir, .allow_read = true, .allow_write = true };
    const char *home = getenv("HOME");
    sandbox_add_home_dir_rule(rules, cap, &n, scratch, scratch_cap, &s, home,
                              ".zclassic-c23-agent-test-status", true);
    if (extra_ro) {
        /* Sapling params dir (read-only proving/verifying keys). */
        sandbox_add_home_dir_rule(rules, cap, &n, scratch, scratch_cap, &s, home, ".zcash-params", false);
        /* DNS resolver config (peer hostname resolution). Grant the /etc/
         * directory read-only only if it exists (it always does on Linux). */
        struct stat est;
        if (n < cap && stat("/etc/resolv.conf", &est) == 0)
            rules[n++] = (struct os_sandbox_path_rule){
                .path = "/etc/resolv.conf", .allow_read = true };
    }
    /* Self-introspection only (getrusage/sysinfo already cover this ground). */
    if (n < cap)
        rules[n++] = (struct os_sandbox_path_rule){
            .path = OS_SANDBOX_PROC_SELF_STATUS_PATH, .allow_read = true };
    return n;
}
/* -confine / -confine=serving (strict seccomp ALLOW-list + Landlock): apply
 * once every listen socket/file/thread is up. An unexpected syscall KILLs the
 * process; actx->confine_serving picks the wider allow-set (adds the socket
 * family) so a node doing real P2P/HTTPS/onion I/O is not SIGSYS-killed at its
 * first accept()/recv()/connect(); plain -confine keeps the strict set.
 * Refuse to HALF-apply: on a partway os_sandbox_enter() failure run the node
 * UNCONFINED and raise 'confine.apply_failed' (remedy OWNER — only an operator
 * can widen the allow-list / enable Landlock and restart) rather than leave a
 * partial sandbox; Landlock degrades gracefully on an older kernel (logged,
 * skipped). Every degrade path returns ZCL_OK, so the REQUEST is noted FIRST —
 * that is the only way the `confinement` witness tells "nobody asked" apart
 * from "asked, and running wide open anyway". */
static struct zcl_result sr_confine_enter(const struct app_context *actx, const char *fallback)
{
    os_sandbox_note_requested(actx->confine_serving ? "node_confine_serving" : "node_confine");
    const char *datadir = actx->datadir ? actx->datadir : fallback;
    if (!datadir || !datadir[0]) {
        /* No datadir to scope: cannot confine safely. Run unconfined + name it. */
        struct blocker_record r;
        if (blocker_init(&r, "confine.apply_failed", "sandbox",
                         BLOCKER_PERMANENT,
                         "-confine requested but no datadir to grant; running "
                         "UNCONFINED (operator must fix the datadir + restart)"))
            (void)blocker_set(&r);
        LOG_WARN("sandbox", "-confine: no datadir to grant; running unconfined "
                 "(blocker confine.apply_failed raised)");
        return ZCL_OK;  /* NOT fatal: unconfined-but-loud, per the -confine contract */
    }
    int abi = os_sandbox_landlock_abi();
    bool seccomp_ok = os_sandbox_seccomp_supported();
    if (abi < 1 && !seccomp_ok) {
        /* Neither mechanism available on this kernel/build: degrade (log+skip),
         * do NOT raise a blocker — this is graceful degradation, not a failure
         * of an applicable request. */
        LOG_WARN("sandbox",
                 "-confine: neither Landlock (abi=%d) nor seccomp available on "
                 "this kernel/build; running unconfined (graceful degrade)", abi);
        return ZCL_OK;
    }
    char scratch[4][PATH_MAX];
    struct os_sandbox_path_rule rules[6];
    size_t n = sandbox_build_fs_rules(datadir, rules, 6, /*extra_ro=*/true,
                                      scratch, 4);
    struct os_sandbox_profile prof = actx->confine_serving
        ? os_sandbox_node_confine_serving_profile(rules, n)
        : os_sandbox_node_confine_profile(rules, n);
    struct zcl_result r = os_sandbox_enter(&prof);
    if (!r.ok) {
        /* Refuse to half-apply: run unconfined + raise the named blocker. Note:
         * a seccomp allow-list that KILLs mid-install would have taken the
         * process down already, so reaching here means an earlier builder
         * (no_new_privs/Landlock) failed cleanly and nothing partial is live. */
        struct blocker_record br;
        char reason[512];
        snprintf(reason, sizeof(reason),
                 "os_sandbox_enter(%s) failed code=%d %s; running "
                 "UNCONFINED (operator must widen the allow-list / enable "
                 "Landlock and restart)",
                 actx->confine_serving ? "node_confine_serving" : "node_confine",
                 r.code, r.message[0] ? r.message : "?");
        if (blocker_init(&br, "confine.apply_failed", "sandbox",
                         BLOCKER_PERMANENT, reason))
            (void)blocker_set(&br);
        LOG_WARN("sandbox", "-confine apply failed (code=%d %s) — running "
                 "unconfined, blocker confine.apply_failed raised",
                 r.code, r.message);
        return ZCL_OK;  /* NOT fatal: the -confine contract is unconfined-but-loud */
    }
    printf("[boot] confine: entered '%s' profile (landlock_abi=%d, %zu fs "
           "grants, seccomp allow-list via %s)\n",
           os_sandbox_active_profile_name() ? os_sandbox_active_profile_name() : "?",
           abi, n, os_sandbox_seccomp_install_method());
    return ZCL_OK;
}
struct zcl_result boot_sandbox_enter(const struct app_context *actx, const char *fallback)
{
    if (!actx)
        return ZCL_OK;
    /* -confine: strict allow-list confinement (distinct from -sandbox=steady;
     * main.c refuses both at once). Unconfined-but-loud on apply failure. */
    if (actx->confine)
        return sr_confine_enter(actx, fallback);
    if (!actx->sandbox_steady)
        return ZCL_OK;  /* -sandbox=off (default): no confinement requested */
    os_sandbox_note_requested("node_steady_state");
    const char *datadir = actx->datadir ? actx->datadir : fallback;
    if (!datadir || !datadir[0])
        return ZCL_ERR(-1, "-sandbox=steady: no datadir to grant");
    char scratch[4][PATH_MAX];
    struct os_sandbox_path_rule rules[3];
    size_t n = sandbox_build_fs_rules(datadir, rules, 3, /*extra_ro=*/false,
                                      scratch, 4);
    struct os_sandbox_profile prof =
        os_sandbox_node_steady_state_profile(rules, n);
    struct zcl_result r = os_sandbox_enter(&prof);
    if (!r.ok) {
        fprintf(stderr,  // obs-ok:sandbox-enter-fatal-precedes-boot-fail
            "FATAL: -sandbox=steady requested but os_sandbox_enter failed: "
            "code=%d %s\n", r.code, r.message);
        return r;
    }
    printf("[boot] sandbox: entered '%s' profile (landlock_abi=%d, %zu fs grants)\n",
           os_sandbox_active_profile_name() ? os_sandbox_active_profile_name() : "?",
           os_sandbox_landlock_abi(), n);
    return ZCL_OK;
}
