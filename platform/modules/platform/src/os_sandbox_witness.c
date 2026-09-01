/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_sandbox_witness — the `confinement` dumpstate subsystem: does this
 * process actually have a kernel filesystem restriction and a system-call
 * filter, or is it running UNCONFINED?
 *
 * Why this is separate from the existing `sandbox` witness: `sandbox` reports
 * the MECHANISM (Landlock ABI, deny-set size, thread coverage). It cannot
 * answer the two questions an operator actually asks —
 *
 *   1. Am I confined right now? `sandbox.active == false` conflates "nobody
 *      asked for confinement" (the default, and fine) with "confinement was
 *      requested and the apply failed, so the node is running wide open"
 *      (engine/composition/src/boot.c:sr_confine_enter's unconfined-but-loud degrade).
 *   2. Where can this process still read and write? The Landlock grant set is
 *      the whole boundary, and nothing surfaced it — you learned it from an
 *      EACCES.
 *
 * Every field here is read from latched/atomic state recorded at apply time.
 * In particular the Landlock ABI is the CACHED value, never a fresh probe:
 * landlock_create_ruleset(2) is absent from both -confine seccomp allow-sets,
 * so probing from inside a confined node is SECCOMP_RET_KILL_PROCESS, not an
 * error return. A diagnostic that kills the process it is diagnosing is worse
 * than no diagnostic.
 *
 * Lives in platform/modules/platform (next to the subsystem it witnesses) rather than in
 * engine/controllers/src/diagnostics_registry.c, which is at its E1 file-size
 * ceiling; the registry only names the function in diagnostics_dumpers.def.
 */

#include "platform/os_sandbox.h"

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool confinement_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    /* ── the headline: is this process confined at all? ──────────────── */
    const bool unconfined = os_sandbox_unconfined();
    const char *requested = os_sandbox_requested_profile();
    const char *active = os_sandbox_active_profile_name();

    json_push_kv_bool(out, "unconfined", unconfined);
    json_push_kv_bool(out, "requested", requested && requested[0]);
    json_push_kv_str(out, "requested_profile", requested ? requested : "");
    json_push_kv_str(out, "active_profile", active ? active : "");

    /* The one state that is a live operator problem: confinement was asked
     * for and the process is running without it anyway. boot raises the
     * blocker 'confine.apply_failed' on that path; this is the same fact
     * readable from the subsystem itself. */
    json_push_kv_bool(out, "requested_but_unconfined",
                      unconfined && requested && requested[0]);

    /* ── filesystem restriction: which interface, which version, what is
     *    actually granted ─────────────────────────────────────────────── */
    const int abi = os_sandbox_landlock_abi_cached();
    json_push_kv_str(out, "fs_restriction_interface",
                     abi >= 0 ? "landlock" : "none");
    json_push_kv_int(out, "fs_restriction_abi", (int64_t)abi);
    json_push_kv_bool(out, "fs_restriction_enforced", abi >= 0);
    json_push_kv_int(out, "landlock_covered_threads",
                     (int64_t)os_sandbox_landlock_restricted_count());

    struct json_value grants;
    json_init(&grants);
    json_set_array(&grants);
    const size_t n = os_sandbox_fs_grant_count();
    for (size_t i = 0; i < n; i++) {
        bool r = false, w = false;
        const char *path = os_sandbox_fs_grant_at(i, &r, &w);
        if (!path)
            break;
        struct json_value g;
        json_init(&g);
        json_set_object(&g);
        json_push_kv_str(&g, "path", path);
        json_push_kv_bool(&g, "read", r);
        json_push_kv_bool(&g, "write", w);
        json_push_back(&grants, &g);
        json_free(&g);
    }
    json_push_kv(out, "fs_grants", &grants);
    json_free(&grants);
    json_push_kv_int(out, "fs_grant_count", (int64_t)n);

    /* ── system-call filter: how it was installed, and what it costs ──── */
    const char *method = os_sandbox_seccomp_install_method();
    json_push_kv_str(out, "syscall_filter_install",
                     method && method[0] ? method : "none");
    json_push_kv_bool(out, "syscall_filter_all_threads",
                      os_sandbox_seccomp_tsync_active());
    json_push_kv_bool(out, "syscall_filter_supported",
                      os_sandbox_seccomp_supported());

    /* A retrofit Landlock join is two syscalls (prctl + landlock_restrict_
     * self). When an allow-list omits them the join is a process KILL, so
     * boot's per-tick retrofit is refused — say so, because it means the
     * threads that predate the domain stay Landlock-unconfined for good. */
    json_push_kv_bool(out, "retrofit_join_permitted",
                      os_sandbox_retrofit_join_permitted());

    return true;
}
