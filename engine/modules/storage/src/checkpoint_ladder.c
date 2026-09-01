/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Checkpoint ladder verifier + dumpstate provider. See
 * storage/checkpoint_ladder.h. Pure verify core (no globals/IO) plus a
 * dumpstate wrapper that loads the compiled keystone + on-disk candidate
 * artifacts and raises a typed blocker on divergence.
 */

#include "storage/checkpoint_ladder.h"

#include "base/bytes.h"
#include "chain/checkpoints.h"
#include "json/json.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/util.h"   /* GetDataDir */

#include <dirent.h>
#include <stdio.h>
#include <string.h>

#define LADDER_SUBSYS "checkpoint_ladder"
#define LADDER_MAX_RUNGS 64
#define LADDER_ARTIFACT_SUBDIR "checkpoint_rungs"
#define LADDER_BLOCKER_ID "checkpoint_ladder.mismatch"

const char *checkpoint_rung_verdict_name(enum checkpoint_rung_verdict v)
{
    switch (v) {
    case CHECKPOINT_RUNG_VERIFIED:     return "verified";
    case CHECKPOINT_RUNG_UNVERIFIABLE: return "unverifiable";
    case CHECKPOINT_RUNG_MISMATCH:     return "MISMATCH";
    }
    return "unknown";
}

/* A compiled keystone with any all-zero shielded field is unbaked (a dev
 * placeholder) — no baked binding is available. Mirrors
 * consensus_state_bundle_validate.c:rom_keystone_is_placeholder. */
static bool keystone_is_placeholder(const struct rom_state_checkpoint *cp)
{
    return !cp ||
           !zcl_bytes_any_set(cp->anchor_digest, 32) ||
           !zcl_bytes_any_set(cp->nullifier_digest, 32) ||
           !zcl_bytes_any_set(cp->sprout_frontier_root, 32) ||
           !zcl_bytes_any_set(cp->sapling_frontier_root, 32) ||
           !zcl_bytes_any_set(cp->utxo_root, 32) ||
           !zcl_bytes_any_set(cp->rom_state_root, 32);
}

size_t checkpoint_ladder_verify(const struct checkpoint_rung *rungs, size_t n,
                                const struct checkpoint_ladder_hooks *hooks,
                                struct checkpoint_ladder_result *out,
                                size_t out_cap, bool *any_mismatch)
{
    if (any_mismatch)
        *any_mismatch = false;
    if (!rungs || !out)
        return 0; // raw-return-ok:pure-verifier-null-guard-no-side-effects
    const struct rom_state_checkpoint *cp = get_rom_state_checkpoint();
    bool have_baked = !keystone_is_placeholder(cp);

    bool have_prev = false;
    int32_t prev_height = 0;
    uint8_t prev_chainwork[32] = {0};

    size_t written = 0;
    for (size_t i = 0; i < n && written < out_cap; i++) {
        const struct checkpoint_rung *r = &rungs[i];
        struct checkpoint_ladder_result *res = &out[written];
        memset(res, 0, sizeof(*res));
        res->height = r->height;
        res->candidate_unbaked = true;
        enum checkpoint_rung_verdict verdict = CHECKPOINT_RUNG_UNVERIFIABLE;
        bool positive_witness = false;

        if (!checkpoint_rung_self_consistent(r)) {
            verdict = CHECKPOINT_RUNG_MISMATCH;
            snprintf(res->detail, sizeof(res->detail),
                     "self-inconsistent: rom_state_root/self_digest do not "
                     "recompute from fields");
            goto record;
        }

        if (have_prev) {
            if (r->height <= prev_height) {
                verdict = CHECKPOINT_RUNG_MISMATCH;
                snprintf(res->detail, sizeof(res->detail),
                         "height %d not strictly greater than prior rung %d",
                         r->height, prev_height);
                goto record;
            }
            if (memcmp(r->chainwork, prev_chainwork, 32) < 0) {
                verdict = CHECKPOINT_RUNG_MISMATCH;
                snprintf(res->detail, sizeof(res->detail),
                         "chainwork decreases vs prior rung at height %d",
                         prev_height);
                goto record;
            }
        }

        /* Baked binding: a rung at the compiled keystone height must reproduce
         * it byte-for-byte (rom_state_root covers all folded fields). */
        if (have_baked && r->height == cp->height) {
            if (memcmp(r->rom_state_root, cp->rom_state_root, 32) == 0) {
                res->bound = true;
                res->candidate_unbaked = false;
                verdict = CHECKPOINT_RUNG_VERIFIED;
                snprintf(res->detail, sizeof(res->detail),
                         "bound: reproduces the compiled sovereign keystone "
                         "byte-for-byte");
            } else {
                verdict = CHECKPOINT_RUNG_MISMATCH;
                snprintf(res->detail, sizeof(res->detail),
                         "divergent artifact: conflicts the compiled keystone "
                         "at its own height %d",
                         cp->height);
                goto record;
            }
        }

        /* Header-chain binding. */
        if (hooks && hooks->block_hash_at) {
            uint8_t hh[32];
            if (hooks->block_hash_at(hooks->ctx, r->height, hh)) {
                if (memcmp(hh, r->block_hash, 32) == 0) {
                    positive_witness = true;
                } else {
                    verdict = CHECKPOINT_RUNG_MISMATCH;
                    snprintf(res->detail, sizeof(res->detail),
                             "block hash does not match the header chain at "
                             "height %d",
                             r->height);
                    goto record;
                }
            }
        }

        /* Root re-derivation where the node holds the state. */
        if (hooks && hooks->rederive_at) {
            struct checkpoint_rung d;
            if (hooks->rederive_at(hooks->ctx, r->height, &d)) {
                uint8_t droot[32];
                checkpoint_rung_compute_rom_state_root(&d, droot);
                if (memcmp(droot, r->rom_state_root, 32) == 0) {
                    positive_witness = true;
                } else {
                    verdict = CHECKPOINT_RUNG_MISMATCH;
                    snprintf(res->detail, sizeof(res->detail),
                             "node-rederived roots differ from the rung at "
                             "height %d",
                             r->height);
                    goto record;
                }
            }
        }

        if (verdict != CHECKPOINT_RUNG_MISMATCH && !res->bound) {
            if (positive_witness) {
                verdict = CHECKPOINT_RUNG_VERIFIED;
                snprintf(res->detail, sizeof(res->detail),
                         "self-consistent; verified against node state "
                         "(candidate_unbaked, not a trust root)");
            } else {
                verdict = CHECKPOINT_RUNG_UNVERIFIABLE;
                snprintf(res->detail, sizeof(res->detail),
                         "self-consistent; no header/rederive/baked witness "
                         "(candidate_unbaked)");
            }
        }

    record:
        res->verdict = verdict;
        if (verdict == CHECKPOINT_RUNG_MISMATCH) {
            if (any_mismatch)
                *any_mismatch = true;
        } else {
            have_prev = true;
            prev_height = r->height;
            memcpy(prev_chainwork, r->chainwork, 32);
        }
        written++;
    }
    return written;
}

/* Insert `r` into the ascending-by-height array of length *count (cap
 * out_cap), preserving order. Silently drops when full. */
static void ladder_insert_sorted(struct checkpoint_rung *arr, size_t *count,
                                 size_t out_cap, const struct checkpoint_rung *r)
{
    if (*count >= out_cap)
        return;
    size_t pos = *count;
    while (pos > 0 && arr[pos - 1].height > r->height) {
        arr[pos] = arr[pos - 1];
        pos--;
    }
    arr[pos] = *r;
    (*count)++;
}

size_t checkpoint_ladder_load_candidates(const char *dir,
                                         struct checkpoint_rung *out,
                                         size_t out_cap)
{
    if (!dir || !out || out_cap == 0)
        return 0; // raw-return-ok:loader-null-guard-no-side-effects
    DIR *d = opendir(dir);
    if (!d) {
        /* Missing artifact dir is the normal (no-ladder) case, not an error. */
        return 0; // raw-return-ok:absent-artifact-dir-is-normal
    }
    size_t count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < out_cap) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 6 || strcmp(ent->d_name + nlen - 5, ".rung") != 0)
            continue;
        char path[2048];
        int pn = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (pn <= 0 || (size_t)pn >= sizeof(path))
            continue;
        FILE *f = fopen(path, "rb");
        if (!f) {
            LOG_WARN(LADDER_SUBSYS, "candidate open failed: %s", path);
            continue;
        }
        uint8_t buf[CHECKPOINT_RUNG_WIRE_SIZE + 1];
        size_t rn = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        struct checkpoint_rung r;
        if (rn != CHECKPOINT_RUNG_WIRE_SIZE ||
            !checkpoint_rung_parse(buf, rn, &r)) {
            LOG_WARN(LADDER_SUBSYS,
                     "candidate rejected (bad size/magic/self-digest): %s",
                     path);
            continue;
        }
        ladder_insert_sorted(out, &count, out_cap, &r);
    }
    closedir(d);
    return count;
}

static void ladder_raise_blocker(int32_t height, const char *detail)
{
    struct blocker_record b;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "checkpoint ladder rung at height %d is MISMATCH: %s", height,
             detail ? detail : "");
    if (!blocker_init(&b, LADDER_BLOCKER_ID, LADDER_SUBSYS, BLOCKER_PERMANENT,
                      reason)) {
        LOG_WARN(LADDER_SUBSYS, "blocker_init failed for ladder mismatch");
        return;
    }
    (void)blocker_set(&b);
}

bool checkpoint_ladder_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false; // raw-return-ok:dumper-null-guard
    json_set_object(out);

    struct checkpoint_rung rungs[LADDER_MAX_RUNGS];
    size_t n = 0;

    const struct rom_state_checkpoint *cp = get_rom_state_checkpoint();
    bool baked_placeholder = keystone_is_placeholder(cp);
    if (cp && !baked_placeholder) {
        struct checkpoint_rung baked;
        if (checkpoint_rung_from_rom_checkpoint(cp, NULL, &baked))
            ladder_insert_sorted(rungs, &n, LADDER_MAX_RUNGS, &baked);
    }

    char datadir[1024] = {0};
    GetDataDir(false, datadir, sizeof(datadir));
    char artifact_dir[1200];
    snprintf(artifact_dir, sizeof(artifact_dir), "%s/%s", datadir,
             LADDER_ARTIFACT_SUBDIR);
    size_t candidates =
        checkpoint_ladder_load_candidates(artifact_dir, rungs + n,
                                          LADDER_MAX_RUNGS - n);
    /* The compiled keystone was inserted first at index 0; candidates were
     * appended past it. Re-sort the whole set so verify() sees ascending
     * heights (candidates may sit below/above the keystone). */
    if (candidates > 0 && n > 0) {
        struct checkpoint_rung merged[LADDER_MAX_RUNGS];
        size_t m = 0;
        for (size_t i = 0; i < n + candidates; i++)
            ladder_insert_sorted(merged, &m, LADDER_MAX_RUNGS, &rungs[i]);
        memcpy(rungs, merged, m * sizeof(rungs[0]));
        n = m;
    } else {
        n += candidates;
    }

    json_push_kv_bool(out, "baked_keystone_present", cp != NULL);
    json_push_kv_bool(out, "baked_keystone_placeholder", baked_placeholder);
    json_push_kv_int(out, "baked_keystone_height", cp ? cp->height : -1);
    json_push_kv_int(out, "candidate_count", (int64_t)candidates);
    json_push_kv_int(out, "rung_count", (int64_t)n);
    json_push_kv_str(out, "artifact_dir", artifact_dir);

    struct checkpoint_ladder_result results[LADDER_MAX_RUNGS];
    bool any_mismatch = false;
    size_t rn = checkpoint_ladder_verify(rungs, n, NULL, results,
                                         LADDER_MAX_RUNGS, &any_mismatch);

    struct json_value arr = {0};
    json_set_array(&arr);
    for (size_t i = 0; i < rn; i++) {
        struct json_value item = {0};
        json_set_object(&item);
        json_push_kv_int(&item, "height", results[i].height);
        json_push_kv_bool(&item, "bound", results[i].bound);
        json_push_kv_str(&item, "trust",
                         results[i].bound ? "baked" : "candidate_unbaked");
        json_push_kv_str(&item, "verdict",
                         checkpoint_rung_verdict_name(results[i].verdict));
        json_push_kv_str(&item, "detail", results[i].detail);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(out, "rungs", &arr);
    json_free(&arr);

    json_push_kv_bool(out, "any_mismatch", any_mismatch);
    if (any_mismatch) {
        int32_t mh = -1;
        const char *md = "";
        for (size_t i = 0; i < rn; i++)
            if (results[i].verdict == CHECKPOINT_RUNG_MISMATCH) {
                mh = results[i].height;
                md = results[i].detail;
                break;
            }
        ladder_raise_blocker(mh, md);
        json_push_kv_str(out, "blocker", LADDER_BLOCKER_ID);
    } else {
        /* No divergence this pass — clear any stale ladder blocker so the
         * subsystem doesn't leave a permanent record after the artifact that
         * tripped it is removed/corrected. */
        blocker_clear(LADDER_BLOCKER_ID);
    }
    return true;
}
