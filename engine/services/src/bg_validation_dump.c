// one-result-type-ok:json-dump-bool — E2 (one way out): the sole public
// function is a best-effort native dump-state JSON view. The convention
// (CLAUDE.md "Adding state introspection") returns bool (false = couldn't
// populate), not struct zcl_result; there is no fallible service surface here.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bg_validation_dump — `z23 dumpstate bg_validation` introspection
 * dumper, split out of bg_validation_service.c so that TU stays under the
 * E1 file-size ceiling. See CLAUDE.md "Adding state introspection".
 *
 * Reads only the public surface: the global service handle g_bg_validation,
 * the lock-free progress snapshot accessor, and the state-name helper. It
 * never changes validation state or advances an authority cursor. */

#include "services/bg_validation_service.h"

#include "json/json.h"

#include <stdbool.h>

/* `z23 dumpstate bg_validation` — historical-proof re-verification
 * progress: state, verified/chain height, sigs+proofs verified, throughput,
 * and the count of post-snapshot blocks whose scripts could not be verified
 * (no undo). Snapshots the service's atomics via the lock-free accessor.
 * Reentrant-safe. */
bool bg_validation_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct bg_validation_service *svc = g_bg_validation;
    json_push_kv_bool(out, "running", svc != NULL);
    if (!svc)
        return true;

    struct bg_validation_progress p = bg_validation_get_progress(svc);
    json_push_kv_str (out, "state",
                      bg_validation_state_name(
                          (enum bg_validation_state)p.state));
    json_push_kv_int (out, "verified_height", p.verified_height);
    json_push_kv_int (out, "chain_height", p.chain_height);
    json_push_kv_int (out, "sigs_verified", p.sigs_verified);
    json_push_kv_int (out, "proofs_verified", p.proofs_verified);
    json_push_kv_int (out, "blocks_per_sec", p.blocks_per_sec);
    json_push_kv_int (out, "script_verif_skipped_no_undo",
                      p.script_verif_skipped_no_undo);
    /* Always-on sampled re-verify (post-COMPLETE): a silent regression of
     * already-verified work surfaces here as reverify_fails > 0. */
    json_push_kv_bool(out, "reverify_active", p.reverify_active);
    json_push_kv_int (out, "reverify_passes", p.reverify_passes);
    json_push_kv_int (out, "reverify_fails", p.reverify_fails);
    json_push_kv_int (out, "reverify_height", p.reverify_height);
    return true;
}
