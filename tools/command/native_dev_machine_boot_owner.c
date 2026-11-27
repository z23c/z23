/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Fixed PUBLIC launch-owner policy, one-shot keyfile delivery and retained joined cleanup. */
#include "native_dev_machine_boot_internal.h"
#include "base/hex.h"
#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "base/log_macros.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "zbase64/zbase64.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Sole-owner protected provider cache.
 * Sole owner serializes all calls; these booleans are NOT synchronization. */
#include "base/cleanse.h"
#include <string.h>
#include <limits.h>

enum cached_phase { CACHED_EMPTY, CACHED_READY, CACHED_LEASED,
                    CACHED_COMMITTED, CACHED_USED, CACHED_TERMINAL };
struct cached_provider {
    struct mesh_guest_protected_tuple admitted;
    struct platform_private_file *credential; /* borrowed, never closed */
    uint8_t key[32];
    uint64_t last_decision;
    enum cached_phase phase;
    bool attempted, revoke_pending, lease_live, read_done;
};
/* PRECONDITION: the sole configuration owner has durably reserved and
 * reconciled generation/high_water through its enrollment/authority record
 * before configure, including after process restart and full host reboot.
 * high_water is the highest previously consumed generation, excluding the
 * current separately reserved candidate. The external durable allocator
 * atomically reserves that candidate; crash reconciliation burns uncertain
 * reservations before another configure. The manager's enrollment extension
 * reserves the candidate; UNKNOWN refuses rather than manufacturing a retry.
 * Ephemeral leases are never restored; that does not permit generation reuse.
 * This memory counter is not a durable allocator or a new authority ledger. */
struct cached_generation_owner { uint64_t high_water; };

static void cached_terminal(struct cached_provider *p)
{
    memory_cleanse(p->key, sizeof(p->key));
    p->phase = CACHED_TERMINAL;
}
static bool cached_tuple_same(const struct cached_provider *p,
                              const struct mesh_guest_protected_tuple *t)
{
    return t && mesh_guest_enrollment_equal(&p->admitted.enrollment, &t->enrollment) &&
        platform_positioned_file_snapshot_equal(&p->admitted.credential, &t->credential) &&
        p->admitted.instance_id == t->instance_id &&
        p->admitted.provider_generation == t->provider_generation &&
        p->admitted.host_epoch == t->host_epoch &&
        p->admitted.device_epoch == t->device_epoch &&
        p->admitted.admitted_ms == t->admitted_ms &&
        p->admitted.delivery_deadline_ms == t->delivery_deadline_ms &&
        p->admitted.authority_expires_ms == t->authority_expires_ms;
}
/* Configure-time I/O only. May block on filesystem; must never run under a
 * stream/instance lock or a governed guest slice. No path open/reconstruction.
 * Caller passes zeroed EMPTY state and actual owner-admitted full tuple. */
static bool cached_configure_admit(const struct cached_provider *p,
    const struct cached_generation_owner *owner,const struct platform_private_file *file,
    const struct mesh_guest_protected_tuple *t)
{
    return p && owner && file && t && p->phase==CACHED_EMPTY && file->locked &&
        t->instance_id && t->host_epoch && t->device_epoch && t->provider_generation &&
        t->provider_generation>owner->high_water && t->admitted_ms &&
        t->delivery_deadline_ms>t->admitted_ms && t->authority_expires_ms>=t->delivery_deadline_ms;
}
static bool cached_snapshot_current(const struct platform_positioned_file *view,
    const struct mesh_guest_protected_tuple *t,struct platform_positioned_file_snapshot *snapshot)
{
    return platform_positioned_file_is_private(view) && platform_positioned_file_is_current_user_only(view) &&
        platform_positioned_file_snapshot(view,snapshot) && snapshot->size==32 &&
        platform_positioned_file_snapshot_equal(snapshot,&t->credential);
}
static bool cached_configure(struct cached_provider *p,
    struct cached_generation_owner *owner, struct platform_private_file *file,
    const struct mesh_guest_protected_tuple *t)
{
    if(!cached_configure_admit(p,owner,file,t))return false;
    owner->high_water = t->provider_generation; /* failure consumes generation */
    struct platform_positioned_file view = {.native=file->native};
    struct platform_positioned_file_snapshot before, after;
    uint8_t bytes[32] = {0}, extra = 0;
    bool ok=cached_snapshot_current(&view,t,&before);
    size_t off = 0;
    while (ok && off < sizeof(bytes)) {
        int64_t n = platform_positioned_file_read(&view, bytes+off, sizeof(bytes)-off, off);
        ok = n > 0 && (uint64_t)n <= sizeof(bytes)-off;
        if (ok) off += (size_t)n;
    }
    if (ok) ok = platform_positioned_file_read(&view, &extra, 1, 32) == 0 &&
        cached_snapshot_current(&view,t,&after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    if (ok) {
        p->admitted = *t; p->credential = file; p->last_decision = t->admitted_ms;
        memcpy(p->key, bytes, sizeof(bytes)); p->phase = CACHED_READY;
    } else cached_terminal(p);
    memory_cleanse(bytes, sizeof(bytes)); memory_cleanse(&extra, sizeof(extra));
    return ok;
}
static enum mesh_guest_provider_result cached_current(void *ctx,
    const struct mesh_guest_protected_tuple *t, uint64_t now)
{
    struct cached_provider *p = ctx;
    if (!p) return MESH_GUEST_PROVIDER_UNKNOWN;
    if (p->phase == CACHED_TERMINAL || p->phase == CACHED_EMPTY || p->revoke_pending)
        return MESH_GUEST_PROVIDER_REFUSED;
    if (!cached_tuple_same(p,t)) return MESH_GUEST_PROVIDER_REFUSED;
    if (now < p->admitted.admitted_ms || now < p->last_decision ||
        now >= p->admitted.authority_expires_ms) {
        cached_terminal(p); return MESH_GUEST_PROVIDER_REFUSED;
    }
    p->last_decision = now;
    return MESH_GUEST_PROVIDER_CURRENT;
}
static bool cached_lease_same(const struct cached_provider *p,
                              const struct mesh_guest_provider_lease *l)
{
    return l && l->id == 1 && l->generation == p->admitted.provider_generation;
}
static enum mesh_guest_provider_result cached_begin(void *ctx,
    const struct mesh_guest_protected_tuple *t, uint64_t now,
    struct mesh_guest_provider_lease *lease)
{
    struct cached_provider *p = ctx;
    if (!p || !lease) return MESH_GUEST_PROVIDER_UNKNOWN;
    *lease = (struct mesh_guest_provider_lease){0};
    if (p->phase != CACHED_READY || p->attempted ||
        cached_current(p,t,now) != MESH_GUEST_PROVIDER_CURRENT)
        return MESH_GUEST_PROVIDER_REFUSED;
    if (now >= p->admitted.delivery_deadline_ms) {
        cached_terminal(p); return MESH_GUEST_PROVIDER_REFUSED;
    }
    p->attempted = true; p->lease_live = true; p->phase = CACHED_LEASED;
    *lease = (struct mesh_guest_provider_lease){.id=1,.generation=t->provider_generation};
    return MESH_GUEST_PROVIDER_CURRENT;
}
static bool cached_read(void *ctx, const struct mesh_guest_protected_tuple *t,
    const struct mesh_guest_provider_lease *lease, uint8_t *out, size_t cap)
{
    struct cached_provider *p = ctx;
    if (!p || !out || cap != 32 || p->phase != CACHED_LEASED || p->read_done || p->revoke_pending ||
        !cached_tuple_same(p,t) || !cached_lease_same(p,lease)) return false;
    memcpy(out,p->key,32); p->read_done = true; /* no I/O; caller wipes scratch */
    return true;
}
static enum mesh_guest_provider_result cached_commit(void *ctx,
    const struct mesh_guest_protected_tuple *t, uint64_t fresh_now,
    const struct mesh_guest_provider_lease *lease)
{
    struct cached_provider *p = ctx;
    if (!p || p->phase != CACHED_LEASED || !p->lease_live || !p->read_done || !cached_lease_same(p,lease))
        return MESH_GUEST_PROVIDER_REFUSED;
    enum mesh_guest_provider_result r = cached_current(p,t,fresh_now);
    if (r == MESH_GUEST_PROVIDER_CURRENT && fresh_now >= p->admitted.delivery_deadline_ms) {
        cached_terminal(p); return MESH_GUEST_PROVIDER_REFUSED;
    }
    if (r == MESH_GUEST_PROVIDER_CURRENT) p->phase = CACHED_COMMITTED;
    return r;
}
static void cached_end(void *ctx, const struct mesh_guest_provider_lease *lease,
    bool delivered)
{
    struct cached_provider *p = ctx;
    if (!p || !p->lease_live || !cached_lease_same(p,lease)) return;
    bool used = delivered && p->phase == CACHED_COMMITTED && !p->revoke_pending;
    memory_cleanse(p->key, sizeof(p->key));
    p->phase = used ? CACHED_USED : CACHED_TERMINAL;
    p->lease_live = false;
}
/* Called only by the serialized owner after external revoke is posted. This
 * is invalidation, NOT ACK/quiescence. A committed receiver queue action orders
 * before revoke; manager must seal pending suffix and stop/quiesce before ACK. */
static void cached_revoke(struct cached_provider *p)
{
    if (!p) return;
    p->revoke_pending = true;
    /* Retain lease_live for end/quiescence; never retain authority or bytes. */
    cached_terminal(p);
}
static struct mesh_guest_secret_provider cached_callbacks(struct cached_provider *p)
{
    return (struct mesh_guest_secret_provider){.context=p,.credential=p->credential,
        .current=cached_current,.begin=cached_begin,.read_key=cached_read,
        .commit_current=cached_commit,.end=cached_end};
}
/* Destroy only AFTER actual successful manager destruction and all leases
 * ended. Owner retains/releases credential separately. No success stub for
 * quiescence, receiver identity, entropy/RNG or accepted-image currentness. */
static bool cached_destroy_after_quiescence(struct cached_provider *p)
{
    if (!p || p->lease_live) return false;
    memory_cleanse(p,sizeof(*p));
    return true;
}
/* Copyright2026 RhettCreighton; SPDX-License-Identifier:Apache-2.0 */
/* Proposed PRIVATE owner cache, never caller/console admission authority. */
enum mb_child_consumer_kind { MB_CHILD_PUBLIC=0, MB_CHILD_PROTECTED_V1 };
struct mb_protected_child_observation {
    enum mb_child_consumer_kind consumer;
    bool image_bound;
    uint8_t helper_sha256[32];
    bool ready,delivered,init_seen,attach_seen,attached_seen,child;
    bool rc6_pending,next_pending,phase6_accepted,consumed_verified;
    const struct rvmachine *ready_machine;
    uint64_t ready_instance,delivery_instance;
    uint32_t ready_host_epoch,ready_device_epoch,delivery_host_epoch,delivery_device_epoch;
};
/* Admission fields only from actual distinct protected image/policy validator.
 * ready fields ONLY from exact protected RECEIVER_READY + actual port checks.
 * delivery fields ONLY actual protected provider freshcommit/exact32 queue
 * observation, never PUBLIC unlock return or guest markers. That manager
 * integration remains required, no invented success setter provided here.
 * Clear observations ONLY successful fresh phase6 dispatch; no failedenqueue
 * reset, replay, copying PUBLICfields or arbitrary caller name selector. */
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Private per-invocation capsule after actual reviewed cache/parser types.
 * Configured once after exact typed protected request + accepted image.
 * Epoch/readiness fields live solely in proof; never copy PUBLIC fields. */
struct mb_protected_owner {
    struct cached_provider provider;
    struct cached_generation_owner generation_owner;
    struct mb_protected_child_observation proof;
    struct mesh_guest_enrollment_record grant;
    uint64_t admitted_ms,delivery_deadline_ms,authority_expires_ms,last_decision;
    const char *extension_path,*reserve_stage_path,*ready_stage_path;
    char *owned_extension_path,*owned_reserve_stage_path,*owned_ready_stage_path;
    bool grant_live,terminal,configure_attempted,create_credential;
    bool health,newfs_done;
    bool trace_bound,trace_invalid,format_completed;
    uint8_t trace_kernel[32],trace_root[32];
    struct mb_v3_dispatch trace_tuple;
    uint64_t health_instance;
    uint32_t health_host_epoch,health_device_epoch;
};
static bool mb_protected_identity_current(const struct mb_state *,uint64_t,uint32_t,uint32_t);
static_assert(offsetof(struct mb_protected_owner,provider)==0,"native provider context is the owner base");
static void mb_owner_protected_line(struct mb_state *,const struct rvmachine *,uint64_t,uint32_t,uint32_t);
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Distinct current-invocation request; no READY checksum creates this grant.
 * Exact top-level accepted-image/capture admission must precede its use. */
struct mb_protected_request {
    const char *volume,*record,*credential,*extension,*reserve_stage,*ready_stage;
    bool recover,create_credential;
};
static bool mb_protected_request_paths(const struct json_value *row,
    struct mb_protected_request *r)
{
    return zcl_mb_boot_opt_str(json_get(row,"volume"),&r->volume)&&r->volume&&
        zcl_mb_boot_opt_str(json_get(row,"record"),&r->record)&&r->record&&
        zcl_mb_boot_opt_str(json_get(row,"credential"),&r->credential)&&r->credential&&
        zcl_mb_boot_opt_str(json_get(row,"extension"),&r->extension)&&r->extension&&
        zcl_mb_boot_opt_str(json_get(row,"reserve_stage"),&r->reserve_stage)&&r->reserve_stage&&
        zcl_mb_boot_opt_str(json_get(row,"ready_stage"),&r->ready_stage)&&r->ready_stage;
}
static bool mb_protected_request_distinct(const struct mb_protected_request *r)
{
    const char *paths[]={r->volume,r->record,r->credential,r->extension,r->reserve_stage,r->ready_stage};
    for(size_t i=0;i<6;i++)for(size_t j=i+1;j<6;j++)if(!strcmp(paths[i],paths[j]))return false;
    return true;
}
static bool mb_protected_request_policy(const struct json_value *row)
{
    const char *policy=NULL,*purpose=NULL,*kernel=NULL;
    int64_t revision=0;
    if(!zcl_mb_boot_opt_str(json_get(row,"policy"),&policy)||!policy||strcmp(policy,"protected_host")||
        !zcl_mb_boot_opt_str(json_get(row,"purpose"),&purpose)||!purpose||strcmp(purpose,"protected_geli_keyfile"))return false;
    if(!zcl_mb_boot_opt_int(json_get(row,"receiver_revision"),0,1,1,&revision)||revision!=1)return false;
    if(!zcl_mb_boot_opt_str(json_get(row,"authorized_kernel_sha256"),&kernel)||!kernel||
        strcmp(kernel,"a5080bb076351c5b5e058a81e5bf6ad3a0f748e97423d2214af5602a5f90097c"))return false;
    return true;
}
static bool mb_protected_request_mode(const struct json_value *row,
    struct mb_protected_request *r)
{
    const char *mode=NULL,*credential_mode=NULL;
    if(!zcl_mb_boot_opt_str(json_get(row,"credential_mode"),&credential_mode)||!credential_mode)return false;
    if(strcmp(credential_mode,"existing_locked_host")&&strcmp(credential_mode,"create_new_host"))return false;
    r->create_credential=!strcmp(credential_mode,"create_new_host");
    if(!zcl_mb_boot_opt_str(json_get(row,"mode"),&mode)||!mode)return false;
    if(strcmp(mode,"initial")&&strcmp(mode,"recover"))return false;
    r->recover=!strcmp(mode,"recover");
    if(r->recover&&r->create_credential)return false;
    return true;
}
static bool mb_protected_request_parse(const struct json_value *row,
    struct mb_protected_request *r)
{
    if(!row || row->type!=JSON_OBJ || row->num_children!=12 || !r)return false;
    memset(r,0,sizeof(*r));
    if(!mb_protected_request_policy(row)||!mb_protected_request_mode(row,r))return false;
    return mb_protected_request_paths(row,r)&&mb_protected_request_distinct(r);
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Root-only precheck never credits a statement. Full checks independently
 * fix exact kernel and all opaque triplet CAS roots before payload loads. */
static bool mb_protected_evidence(const struct vcs_guest_image_observation *o)
{
    static const char *const roots[]={
        "aa328b17482b96702d75c9b7130eda5d5d0ddcb7c420a326f554f03fc6e28290",
        "92bd02a780f54b3ecc768cc569b538270bc26522302b1f07a707c401b7e9c140",
        "78655ca665ffe66b8aca3d98f21a19a7b56c914a179a35ced554e358f304a530"};
    static const uint64_t sizes[]={15372,28233,91141};
    for(size_t i=0;i<3;i++){
        uint8_t fixed[32];
        if(!zcl_hex_decode_lower(roots[i],fixed,32) || o->evidence[i].bytes!=sizes[i] ||
            memcmp(o->evidence[i].root,fixed,32))return false;
    }
    return true;
}
static bool mb_protected_image_grant(struct mb_state *st,const uint8_t root[32],
    const struct vcs_guest_image_observation *o)
{
    if(!st || !root || !st->owner.protected || !st->owner.enabled ||
        !st->accepted.protected_observation || st->accepted.public_observation ||
        st->owner.failed || st->entropy_failed || memcmp(root,st->accepted.root,32))return false;
    uint8_t kernel[32];
    if(!zcl_hex_decode_lower("a5080bb076351c5b5e058a81e5bf6ad3a0f748e97423d2214af5602a5f90097c",kernel,32) ||
        memcmp(kernel,st->owner.authorized_kernel,32))return false;
    return !o || (o->image.bytes==UINT64_C(43412608) &&
        !memcmp(o->image_sha256,kernel,32) && mb_protected_evidence(o));
}
/* One called PUBLIC owner at a time. A refused join keeps its heap capsule
 * reachable and denies another admission until this process exits; no charge,
 * descriptor or callback context is freed by pretending destruction worked. */
static _Atomic bool mb_public_owner_busy;
[[maybe_unused]] static struct mb_state *mb_public_owner_retained;

/* Each revision fixes its image independently of unsigned CAS observations. */
struct mb_owner_profile {
    const char *kernel, *root, *guest, *profile, *grant, *helper;
};
static const struct mb_owner_profile *mb_owner_profile(unsigned revision)
{
    static const struct mb_owner_profile rows[] = {
        {"2445a0ca747bb28eac52c8c2bb861ee9be06f3c7353587d88e3c3fcbb832b2f4",
         "5e1205cf0ff719d207264826bd88393eb0e65add633fb5889f90d55be6280d06",
         "z23.PUBLIC.geli.owner.guest.v1", "z23.PUBLIC.geli.owner.profile.v1",
         "local.operator.PUBLIC.geli.keyfile.v1",
         "274880bbfd8a46a278d78c5e765a76c4299d107ced67f583e676993b826c8e5f"},
        {"db2440c0ce534decbac8aac94fade789c8978e5d145f1795fa216603a7404af5",
         "66298db371101e5085cd88abfaf4b5835208ae75b441d4fdd3a325fa72741ae9",
         "z23.PUBLIC.geli.owner.guest.v2", "z23.PUBLIC.geli.owner.profile.v2",
         "local.operator.PUBLIC.geli.keyfile.v2",
         "274880bbfd8a46a278d78c5e765a76c4299d107ced67f583e676993b826c8e5f"},
        {"ac1dd2f5260aa64d2ba9cf30c13927709ff7f427709571dd65521051cf44b57c",
         "ae126a37ac11db4203992f905c5a4a14ceb2668bb67fd3b861f704cdcde0e7a8",
         "z23.PUBLIC.geli.owner.guest.v3", "z23.PUBLIC.geli.owner.profile.v3",
         "local.operator.PUBLIC.geli.keyfile.v3",
         "716e739adbd37ca284765790267cc1e973f82686359a6cbe7993d060ac91e9f4"},
        {"fca910590d9b3171712883285fb30743b30f7715a4b8fb41c17a51bfdcca6a6e",
         "ae126a37ac11db4203992f905c5a4a14ceb2668bb67fd3b861f704cdcde0e7a8",
         "z23.PUBLIC.geli.owner.guest.v4", "z23.PUBLIC.geli.owner.profile.v4",
         "local.operator.PUBLIC.geli.keyfile.v4",
         "716e739adbd37ca284765790267cc1e973f82686359a6cbe7993d060ac91e9f4"},
        {"c7df418c75c63125a6ea77edba7b654486c5912bc1fd60c53fcc39778dbb1bf7",
         "ae126a37ac11db4203992f905c5a4a14ceb2668bb67fd3b861f704cdcde0e7a8",
         "z23.PUBLIC.geli.owner.guest.v5", "z23.PUBLIC.geli.owner.profile.v5",
         "local.operator.PUBLIC.geli.keyfile.v5",
         "716e739adbd37ca284765790267cc1e973f82686359a6cbe7993d060ac91e9f4"},
        {"82d6598d9669339eb9890d9c8b5152597beac22cbfc5c86200a23f1dc2cd3562",
         "ae126a37ac11db4203992f905c5a4a14ceb2668bb67fd3b861f704cdcde0e7a8",
         "z23.PUBLIC.geli.owner.guest.v6", "z23.PUBLIC.geli.owner.profile.v6",
         "local.operator.PUBLIC.geli.keyfile.v6",
         "716e739adbd37ca284765790267cc1e973f82686359a6cbe7993d060ac91e9f4"},
        {"f7e7379fb08fd0035cf67bd98d5896376e103ab80851363d2c1f1a16a53e675d",
         "9541a135ed646af120c182fb19b7586a8f3ead63b1edd1cc880d8f584c674cac",
         "z23.PUBLIC.geli.owner.guest.v7", "z23.PUBLIC.geli.owner.profile.v7",
         "local.operator.PUBLIC.geli.keyfile.v7",
         "716e739adbd37ca284765790267cc1e973f82686359a6cbe7993d060ac91e9f4"}

    };
    return revision >= 1 && revision <= 7 ? &rows[revision-1] : NULL;
}
static bool mb_owner_prepared_profile(const struct mb_state *st)
{
    return st->owner.profile_revision >= 3 && st->owner.profile_revision <= 7;
}
static uint64_t mb_owner_image_bytes(const struct mb_state *st)
{
    if (st->owner.profile_revision == 4) return UINT64_C(43408024);
    if (st->owner.profile_revision == 6 || st->owner.profile_revision == 7) return UINT64_C(43412608);
    if (st->owner.profile_revision == 5) return UINT64_C(43406744);
    return mb_owner_profile(st->owner.profile_revision) ? UINT64_C(43407928) : 0;
}
static bool mb_owner_typed_profile(const struct mb_state *st)
{
    return st->owner.protected || st->owner.profile_revision == 2 || mb_owner_prepared_profile(st);
}
static bool mb_owner_profile_parse(const struct json_value *row, struct mb_state *st)
{
    const struct json_value *field=json_get(row,"profile_revision");
    int64_t revision=1;
    if (field && !zcl_mb_boot_opt_int(field,0,2,7,&revision)) return false;
    if (row->num_children != (field ? 9u : 8u)) return false;
    st->owner.profile_revision=(uint32_t)revision;
    return true;
}

static bool mb_owner_policy_row(const struct json_value *row)
{
    const char *policy = NULL, *purpose = NULL;
    int64_t revision = 0;
    return row->type == JSON_OBJ &&
        zcl_mb_boot_opt_str(json_get(row, "policy"), &policy) && policy &&
        !strcmp(policy, "public_keyfile_fixture") &&
        zcl_mb_boot_opt_str(json_get(row, "purpose"), &purpose) && purpose &&
        !strcmp(purpose, "public_geli_keyfile") &&
        zcl_mb_boot_opt_int(json_get(row, "receiver_revision"), 0, 1, 1, &revision) && revision == 1;
}
static bool mb_owner_destinations(const struct json_value *row, struct mb_state *st)
{
    return zcl_mb_boot_opt_str(json_get(row, "volume"), &st->owner.volume_path) && st->owner.volume_path &&
        zcl_mb_boot_opt_str(json_get(row, "record"), &st->owner.record_path) && st->owner.record_path &&
        zcl_mb_boot_opt_str(json_get(row, "credential"), &st->owner.credential_path) && st->owner.credential_path;
}
static bool mb_owner_public_options(const struct json_value *in, const struct mb_state *st)
{
    return st->accepted.datadir && st->host_entropy && st->early && !st->seeded &&
        !st->kernel.path && !st->disk.path && !st->transcript && !st->bootargs &&
        !st->port_count && !json_get(in, "until") && !json_get(in, "type_after");
}
static bool mb_owner_consumer_row(const struct json_value *row, struct mb_state *st,
    const char **mode)
{
    const char *digest = NULL;
    return zcl_mb_boot_opt_str(json_get(row, "mode"), mode) && *mode &&
        (!strcmp(*mode, "initial") || !strcmp(*mode, "recover")) &&
        zcl_mb_boot_opt_str(json_get(row, "authorized_kernel_sha256"), &digest) && digest &&
        zcl_hex_decode_lower(digest, st->owner.authorized_kernel, 32) &&
        mb_owner_profile(st->owner.profile_revision) &&
        !strcmp(digest, mb_owner_profile(st->owner.profile_revision)->kernel);
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
static bool mb_owner_protected_parse(const struct json_value *in,const struct json_value *row,
    struct mb_state *st,struct zcl_command_reply *reply)
{
    struct mb_protected_request r;
    if(json_get(in,"builtin_kernel") || json_get(in,"data_disk") || json_get(in,"home") ||
        !st->accepted.protected_observation || st->accepted.public_observation ||
        !mb_protected_request_parse(row,&r) || !mb_owner_public_options(in,st))
        return zcl_mb_boot_bad_input(reply,"protected_unlock requires the distinct protected copied image and current host owner policy");
    struct mb_protected_owner *p=zcl_calloc(1,sizeof(*p),"protected owner capsule");
    if(!p)return zcl_mb_boot_fail(reply,ZCL_COMMAND_EXIT_INTERNAL,"OUT_OF_MEMORY","admit",
        "protected owner capsule allocation refused",MB_PATH);
    st->owner.protected=p;
    p->create_credential=r.create_credential;
    p->extension_path=r.extension;p->reserve_stage_path=r.reserve_stage;p->ready_stage_path=r.ready_stage;
    st->owner.volume_path=r.volume;st->owner.record_path=r.record;st->owner.credential_path=r.credential;
    st->owner.recover=r.recover;
    if(!zcl_hex_decode_lower("a5080bb076351c5b5e058a81e5bf6ad3a0f748e97423d2214af5602a5f90097c",
        st->owner.authorized_kernel,32))return false;
    p->proof.consumer=MB_CHILD_PROTECTED_V1;
    p->proof.image_bound=false;
    if(!zcl_hex_decode_lower("194bd9c2977dcab3c340472d10f8291c266bdc6fff463d0223f130886c396c4e",
        p->proof.helper_sha256,32))return false;
    st->owner.enabled=true;
    return true;
}
bool zcl_mb_owner_parse(const struct json_value *in, struct mb_state *st,
    struct zcl_command_reply *reply)
{
    const struct json_value *row = json_get(in, "public_unlock");
    const struct json_value *protected_row=json_get(in,"protected_unlock");
    if(protected_row){
        if(row)return zcl_mb_boot_bad_input(reply,"PUBLIC and protected owner policies are mutually exclusive");
        return mb_owner_protected_parse(in,protected_row,st,reply);
    }
    if(st->accepted.protected_observation)
        return zcl_mb_boot_bad_input(reply,"protected_kernel requires its distinct protected owner");
    if (!row) {
        if (st->accepted.public_observation)
            return zcl_mb_boot_bad_input(reply, "public_kernel requires the fixed PUBLIC unlock owner");
        return true;
    }
    const char *mode = NULL;
    if (!mb_owner_policy_row(row) || !mb_owner_profile_parse(row, st) || !mb_owner_consumer_row(row, st, &mode) ||
        !mb_owner_destinations(row, st))
        return zcl_mb_boot_bad_input(reply, "public_unlock requires the fixed PUBLIC policy, consumer, purpose and revision");
    if (!mb_owner_public_options(in, st))
        return zcl_mb_boot_bad_input(reply, "PUBLIC unlock requires an installed or fixed PUBLIC image and host seed with no public export or script options");
    if (!strcmp(st->owner.volume_path, st->owner.record_path) ||
        !strcmp(st->owner.volume_path, st->owner.credential_path) ||
        !strcmp(st->owner.record_path, st->owner.credential_path))
        return zcl_mb_boot_bad_input(reply, "PUBLIC volume, record and input destinations must be distinct");
    st->owner.enabled = true;
    st->owner.recover = strcmp(mode, "recover") == 0;
    return true;
}

enum { MB_OWNER_KEY_COMMAND = 14, MB_OWNER_FINGERPRINT_COMMAND = 15 };

/* Fixed PUBLIC grammar only. The caller separately binds phase, instance and
 * both port generations. Output storage must not alias the input line. */
static bool mb_owner_wire_line(const uint8_t *line, size_t n,
    struct mb_public_identity *out,const char *prefix,const char *suffix)
{
    size_t start=strlen(prefix),end=strlen(suffix);
    if (!out) return false;
    *out = (struct mb_public_identity){0};
    if (!line || n != start+68+end || memcmp(line,prefix,start) ||
        memcmp(line+start+68,suffix,end)) return false;
    struct mb_public_identity parsed = {0};
    size_t produced = 0;
    if (!zbase64_decode((const char *)line+start, 68,
            parsed.wire, sizeof(parsed.wire), &produced) ||
        produced != sizeof(parsed.wire) || zcl_read_u32_be(parsed.wire) != 11 ||
        memcmp(parsed.wire + 4, "ssh-ed25519", 11) ||
        zcl_read_u32_be(parsed.wire + 15) != 32) return false;
    struct sha256_ctx hash;
    sha256_init(&hash); sha256_write(&hash, parsed.wire, sizeof(parsed.wire));
    sha256_finalize(&hash, parsed.fingerprint);
    *out = parsed;
    return true;
}
static bool mb_owner_public_wire_line(const uint8_t *line,size_t n,
    struct mb_public_identity *out)
{
    return mb_owner_wire_line(line,n,out,"PUBLIC_V2_KEY:ssh-ed25519 "," z23-fixture-host\r\n");
}
/* All three buffers are distinct. A fingerprint display is accepted only
 * when it equals the hash of the independently parsed complete SSH wire. */
static bool mb_owner_fingerprint_exact_line(const uint8_t *line, size_t n,
    const uint8_t expected[32], uint8_t out[32],const char *suffix)
{
    static const char prefix[] = "256 SHA256:";
    size_t end=strlen(suffix);
    if (!out) return false;
    memset(out, 0, 32);
    if (!line || !expected || n != sizeof(prefix)-1+43+end || memcmp(line, prefix, sizeof(prefix) - 1) ||
        memcmp(line + sizeof(prefix) - 1 + 43,suffix,end)) return false;
    char encoded[44];
    memcpy(encoded, line + sizeof(prefix) - 1, 43); encoded[43] = '=';
    uint8_t parsed[32] = {0}; size_t produced = 0;
    if (!zbase64_decode(encoded, sizeof(encoded), parsed, sizeof(parsed), &produced) ||
        produced != sizeof(parsed) || memcmp(parsed, expected, sizeof(parsed))) return false;
    memcpy(out, parsed, sizeof(parsed));
    return true;
}
static bool mb_owner_fingerprint_line(const uint8_t *line,size_t n,
    const uint8_t expected[32],uint8_t out[32])
{
    return mb_owner_fingerprint_exact_line(line,n,expected,out," z23-fixture-host (ED25519)\r\n");
}
static bool mb_owner_identity_current(const struct mb_state *st, uint64_t instance,
    uint32_t epoch, uint32_t device_epoch)
{
    if(st->owner.protected)return mb_protected_identity_current(st,instance,epoch,device_epoch);
    return !st->owner.failed && !st->entropy_failed && st->owner.health &&
        st->owner.child && st->owner.delivered && st->owner.instance == instance &&
        st->owner.health_instance == instance && st->owner.ready_epoch == epoch &&
        st->owner.health_epoch == epoch && st->owner.ready_device_epoch == device_epoch &&
        st->owner.health_device_epoch == device_epoch;
}
static void mb_owner_identity_observe(struct mb_state *st, uint64_t instance,
    uint32_t epoch, uint32_t device_epoch)
{
    if (!mb_owner_typed_profile(st)) return;
    const uint8_t *line = st->owner.line;
    size_t n = st->owner.line_length;
    if (n >= 14 && !memcmp(line, "PUBLIC_V2_KEY:", 14)) {
        if (!mb_owner_identity_current(st, instance, epoch, device_epoch) ||
            st->owner.command_step != MB_OWNER_KEY_COMMAND + 1 || st->owner.public_key_seen ||
            !mb_owner_public_wire_line(line, n, &st->owner.identity)) st->owner.failed = true;
        else st->owner.public_key_seen = true;
    } else if (n >= 11 && !memcmp(line, "256 SHA256:", 11)) {
        uint8_t observed[32];
        if (!mb_owner_identity_current(st, instance, epoch, device_epoch) ||
            st->owner.command_step != MB_OWNER_FINGERPRINT_COMMAND + 1 ||
            !st->owner.public_key_seen || st->owner.fingerprint_seen ||
            !mb_owner_fingerprint_line(line, n, st->owner.identity.fingerprint, observed))
            st->owner.failed = true;
        else st->owner.fingerprint_seen = true;
    }
}

static bool mb_command_begin(struct mb_command_observation *s, unsigned phase,
    uint64_t instance, uint32_t host_epoch, uint32_t device_epoch)
{
    if (!s || !instance || !host_epoch || !device_epoch || phase < 1 || phase > 16 ||
        (s->active && !s->next_seen)) return false;
    *s = (struct mb_command_observation){.instance=instance, .host_epoch=host_epoch,
        .device_epoch=device_epoch, .phase=phase, .active=true};
    return true;
}
static bool mb_command_current(const struct mb_command_observation *s,
    unsigned phase, uint64_t instance, uint32_t host_epoch, uint32_t device_epoch)
{
    return s && s->active && s->phase == phase && s->instance == instance &&
        s->host_epoch == host_epoch && s->device_epoch == device_epoch;
}
/* Decimal digits only, no signs/whitespace/leading zeros, bounded arithmetic. */
static bool mb_command_decimal(const uint8_t *p, size_t n, unsigned max, unsigned *out)
{
    if (!n || n > 3 || (n > 1 && p[0] == '0')) return false;
    unsigned value = 0;
    for (size_t i=0; i<n; i++) {
        if (p[i] < '0' || p[i] > '9') return false;
        value = value * 10 + (unsigned)(p[i] - '0');
    }
    if (value > max) return false;
    *out = value;
    return true;
}
static bool mb_command_rc(const uint8_t *line, size_t n, unsigned *phase, unsigned *rc)
{
    static const char prefix[]="PUBLIC_V2_RC:";
    if (!line || n < 18 || n > 21 || memcmp(line,prefix,13) ||
        line[n-2] != '\r' || line[n-1] != '\n') return false;
    size_t colon=13;
    while (colon < n-2 && line[colon] != ':') colon++;
    return colon < n-2 && mb_command_decimal(line+13,colon-13,16,phase) &&
        *phase != 0 && mb_command_decimal(line+colon+1,n-colon-3,255,rc);
}
/* Called only for RC/NEXT/DONE whole lines after existing line epoch validation.
 * False is fatal refusal. Unknown lines remain outer parser's responsibility. */
static bool mb_command_accept_rc(struct mb_command_observation *s, const uint8_t *line, size_t n, bool key_seen, bool fingerprint_seen)
{
    unsigned phase=0, rc=0;
    if (s->rc_seen || !mb_command_rc(line,n,&phase,&rc) || phase != s->phase || rc) return false;
    if ((phase == 14 && !key_seen) || (phase == 15 && !fingerprint_seen)) return false;
    s->rc_seen=true;
    return true;
}
static bool mb_command_accept_done(struct mb_command_observation *s, bool key_seen, bool fingerprint_seen, bool child_ok, bool *done)
{
    if (!s->rc_seen || s->done_seen || s->phase != 16 || !key_seen || !fingerprint_seen || !child_ok) return false;
    s->done_seen=true; *done=true;
    return true;
}
static bool mb_command_observe(struct mb_command_observation *s,
    const uint8_t *line, size_t n, unsigned dispatched_phase, uint64_t instance,
    uint32_t host_epoch, uint32_t device_epoch, bool key_seen, bool fingerprint_seen,
    bool child_ok, bool *pending, bool *done)
{
    if (!mb_command_current(s,dispatched_phase,instance,host_epoch,device_epoch)) return false;
    if (n >= 13 && !memcmp(line,"PUBLIC_V2_RC:",13)) {
        return mb_command_accept_rc(s,line,n,key_seen,fingerprint_seen);
    }
    if (n == 19 && !memcmp(line,"PUBLIC_OWNER_NEXT\r\n",19)) {
        if (!s->rc_seen || s->next_seen || s->phase == 16) return false;
        s->next_seen=true; *pending=true;
        return true;
    }
    if (n == 19 && !memcmp(line,"PUBLIC_OWNER_DONE\r\n",19)) {
        return mb_command_accept_done(s,key_seen,fingerprint_seen,child_ok,done);
    }
    return false;
}

static bool mb_owner_prepare_rc_ready(const struct mb_state *st,
    const uint8_t *line, size_t n)
{
    if (!mb_owner_prepared_profile(st) || st->owner.recover ||
        st->owner.command.phase != 6 || n < 13 || memcmp(line, "PUBLIC_V2_RC:", 13))
        return true;
    return st->owner.prepared20k_seen && st->owner.child && st->owner.delivered;
}
static bool mb_owner_command_line(struct mb_state *st, uint64_t instance,
    uint32_t epoch, uint32_t device_epoch)
{
    if (!mb_owner_typed_profile(st)) return false;
    const uint8_t *line = st->owner.line;
    size_t n = st->owner.line_length;
    bool control = (n >= 13 && !memcmp(line, "PUBLIC_V2_RC:", 13)) ||
        !strcmp((const char *)line, "PUBLIC_OWNER_NEXT\r\n") ||
        !strcmp((const char *)line, "PUBLIC_OWNER_DONE\r\n");
    if (!control) return false;
    if (!mb_owner_prepare_rc_ready(st, line, n)) {
        st->owner.failed = true;
        return true;
    }
    if (st->owner.failed || !st->owner.command_step ||
        !mb_command_observe(&st->owner.command, line, n,
            (unsigned)(st->owner.command_step - 1), instance, epoch, device_epoch,
            st->owner.public_key_seen, st->owner.fingerprint_seen, st->owner.child,
            &st->owner.command_pending, &st->owner.done)) st->owner.failed = true;
    return true;
}

static bool mb_owner_bootstrap_phase(const struct mb_state *st, uint64_t instance,
    uint32_t epoch, uint32_t device_epoch)
{
    if (!mb_owner_typed_profile(st)) return true;
    const char *line = (const char *)st->owner.line;
    if (!strcmp(line, "PUBLIC_OWNER_HEALTH\r\n"))
        return !st->owner.health && st->owner.command.rc_seen &&
            mb_command_current(&st->owner.command, 4, instance, epoch, device_epoch);
    if (!strcmp(line, "PUBLIC_BOOTSTRAP_RAW_READY\r\n") ||
        !strcmp(line, "PUBLIC_BOOTSTRAP_CHILD delivered32=1 eof=1 reaped=1 timely=1 exited=1 status=0\r\n"))
        return mb_command_current(&st->owner.command, 6, instance, epoch, device_epoch);
    return true;
}

static bool mb_owner_phase7_current(const struct mb_state *st, uint64_t instance,
    uint32_t host_epoch, uint32_t device_epoch)
{
    return st->owner.profile_revision == 2 && !st->owner.recover &&
        !st->owner.failed && st->owner.command_step == 8 && !st->owner.command.rc_seen &&
        mb_command_current(&st->owner.command, 7, instance, host_epoch, device_epoch);
}
static bool mb_owner_phase7_sequence(struct mb_state *st, uint8_t marker)
{
    if (marker == 'A') {
        if (st->owner.phase7_dd_done || st->owner.phase7_newfs_done) return false;
        st->owner.phase7_dd_done = true;
        return true;
    }
    if (marker == 'B') {
        if (!st->owner.phase7_dd_done || st->owner.phase7_newfs_done) return false;
        st->owner.phase7_newfs_done = true;
        return true;
    }
    return false;
}
/* Fixed public progress observations only; RC and storage remain authoritative. */
struct mg_cursor { const uint8_t *p; size_t n, at; };
static bool mg_text(struct mg_cursor *c, const char *s)
{
    size_t n=strlen(s);
    if (n>c->n-c->at || memcmp(c->p+c->at,s,n)) return false;
    c->at+=n; return true;
}
static bool mg_u32(struct mg_cursor *c, uint32_t *out)
{
    size_t start=c->at; uint32_t v=0;
    while(c->at<c->n && c->p[c->at]>='0' && c->p[c->at]<='9') {
        uint32_t d=c->p[c->at]-'0';
        if(c->at-start>=10 || v>(UINT32_MAX-d)/10) return false;
        v=v*10+d; ++c->at;
    }
    if(c->at==start || (c->at-start>1 && c->p[start]=='0')) return false;
    *out=v; return true;
}
static bool mg_decimal_skip(struct mg_cursor *c)
{
    uint32_t ignored=0;
    if(!mg_u32(c,&ignored) || !mg_text(c,".")) return false;
    if(c->n-c->at<2) return false;
    for(unsigned i=0;i<2;++i) {
        if(c->p[c->at]<'0'||c->p[c->at]>'9') return false;
        ++c->at;
    }
    return mg_text(c,"MB, ");
}
static bool mg_fields(struct mg_cursor *c, struct mb_newfs_geometry *v)
{
    return mg_u32(c,&v->groups) && v->groups &&
        mg_text(c," cylinder groups of ") && mg_decimal_skip(c) &&
        mg_u32(c,&v->blocks) && v->blocks && mg_text(c," blks, ") &&
        mg_u32(c,&v->inodes) && v->inodes && mg_text(c," inodes.\r\n");
}
static bool mb_newfs_geometry_line(const uint8_t *line,size_t n,
    struct mb_newfs_geometry *out)
{
    if(!line||!out||n>128) return false;
    struct mg_cursor c={line,n,0}; struct mb_newfs_geometry v={0};
    if(!mg_text(&c,"\tusing ")) {
        c.at=0;
        if(!mg_text(&c,"        using ")) return false;
    }
    if(!mg_fields(&c,&v) || c.at!=c.n) return false;
    *out=v; return true;
}
static bool mb_owner_pc_scope(struct mb_state *st);
static bool mb_owner_pc_formatting(const struct mb_state *st)
{
    if (st->owner.profile_revision == 2)
        return st->owner.phase7_dd_done && !st->owner.phase7_newfs_done;
    return mb_owner_prepared_profile(st) && st->owner.prepared20k_seen &&
        !st->owner.v3_newfs_done;
}
static bool mb_owner_pc_phase7_current(const struct mb_state *st, uint64_t instance,
    uint32_t host_epoch, uint32_t device_epoch)
{
    if (st->owner.profile_revision == 2)
        return mb_owner_phase7_current(st, instance, host_epoch, device_epoch);
    return mb_owner_prepared_profile(st) && !st->owner.recover &&
        !st->owner.failed && st->owner.command_step == 8 &&
        !st->owner.command.rc_seen && mb_owner_pc_formatting(st) &&
        mb_command_current(&st->owner.command, 7, instance, host_epoch, device_epoch);
}
static bool mb_geometry_prefix(const uint8_t *line, size_t n)
{
    return (n >= 7 && !memcmp(line,"\tusing ",7)) ||
        (n >= 14 && !memcmp(line,"        using ",14));
}
static bool mb_geometry_bounded(const struct mb_newfs_geometry *v)
{
    return v->groups && v->groups <= UINT16_MAX && v->blocks &&
        v->blocks <= UINT16_MAX && v->inodes && v->inodes <= UINT16_MAX;
}
static void mb_owner_geometry_observe(struct mb_state *st, uint64_t instance,
    uint32_t epoch, uint32_t device_epoch)
{
    if (!mb_owner_pc_scope(st) || !mb_owner_pc_formatting(st) ||
        !mb_owner_pc_phase7_current(st,instance,epoch,device_epoch) ||
        !mb_owner_identity_current(st,instance,epoch,device_epoch) ||
        !mb_geometry_prefix(st->owner.line,st->owner.line_length)) return;
    struct mb_newfs_geometry value;
    if (st->owner.geometry_seen || st->owner.geometry_unqualified ||
        !mb_newfs_geometry_line(st->owner.line,st->owner.line_length,&value) ||
        !mb_geometry_bounded(&value)) {
        st->owner.geometry_unqualified = true;
        return;
    }
    st->owner.geometry = value;
    st->owner.geometry_seen = true;
}
static bool mb_owner_phase7_line(struct mb_state *st, const uint8_t *line, size_t n,
    uint64_t instance, uint32_t host_epoch, uint32_t device_epoch)
{
    if (n < 2 || memcmp(line, "P7", 2)) return false;
    if (n != 5 || line[3] != '\r' || line[4] != '\n' ||
        !mb_owner_phase7_current(st, instance, host_epoch, device_epoch) ||
        !mb_owner_phase7_sequence(st, line[2])) st->owner.failed = true;
    return true;
}

static bool mb_owner_bootstrap_current(const struct mb_state *st, uint64_t instance,
    uint32_t epoch, uint32_t device_epoch)
{
    return st->owner.instance == instance && st->owner.ready_epoch == epoch &&
        st->owner.ready_device_epoch == device_epoch;
}

/* V3 formatter completion is diagnostic only, before mounting in phase7. */
static bool mb_owner_v3_newfs_line(struct mb_state *st, uint64_t instance,
    uint32_t epoch, uint32_t device_epoch)
{
    if (!mb_owner_prepared_profile(st) ||
        strcmp((const char *)st->owner.line,"PUBLIC_V3_NEWFS_DONE\r\n")) return false;
    if (st->owner.failed || st->owner.recover || st->owner.v3_newfs_done ||
        !st->owner.prepared20k_seen || !st->owner.child || !st->owner.delivered ||
        st->owner.command_step!=8 || st->owner.command.rc_seen ||
        !mb_owner_bootstrap_current(st,instance,epoch,device_epoch) ||
        !mb_command_current(&st->owner.command,7,instance,epoch,device_epoch))
        st->owner.failed=true;
    else st->owner.v3_newfs_done=true;
    return true;
}
static const char *mb_owner_v3_newfs_summary(const struct mb_state *st)
{
    if (!mb_owner_prepared_profile(st) || st->owner.recover) return "";
    return st->owner.v3_newfs_done ? " newfs=1" : " newfs=0";
}

/* V3 INITIAL preparation is observed once, before successful phase6 RC. */
static bool mb_owner_prepare_line(struct mb_state *st, uint64_t instance,
    uint32_t epoch, uint32_t device_epoch)
{
    if (!mb_owner_prepared_profile(st)) return false;
    static const char marker[] = "PUBLIC_BOOTSTRAP_PREPARED20K\r\n";
    if (strcmp((const char *)st->owner.line, marker)) return false;
    if (st->owner.failed || st->owner.recover || st->owner.prepared20k_seen ||
        st->owner.command_step != 7 || st->owner.command.rc_seen ||
        !st->owner.child || !st->owner.delivered ||
        !mb_owner_bootstrap_current(st, instance, epoch, device_epoch) ||
        !mb_command_current(&st->owner.command, 6, instance, epoch, device_epoch))
        st->owner.failed = true;
    else st->owner.prepared20k_seen = true;
    return true;
}

static bool mb_owner_v3_line(struct mb_state *st, uint64_t instance,
    uint32_t epoch, uint32_t device_epoch)
{
    return mb_owner_v3_newfs_line(st, instance, epoch, device_epoch) ||
        mb_owner_prepare_line(st, instance, epoch, device_epoch);
}
static void mb_owner_public_line(struct mb_state *st, const struct rvmachine *machine,
    uint64_t instance, uint32_t epoch, uint32_t device_epoch)
{
    if (mb_owner_v3_line(st, instance, epoch, device_epoch)) return;
    mb_owner_geometry_observe(st,instance,epoch,device_epoch);
    if (st->owner.profile_revision == 2 && mb_owner_phase7_line(st,
        st->owner.line, st->owner.line_length, instance, epoch, device_epoch)) return;
    mb_owner_identity_observe(st, instance, epoch, device_epoch);
    if (mb_owner_command_line(st, instance, epoch, device_epoch)) return;
    if (!mb_owner_bootstrap_phase(st, instance, epoch, device_epoch)) {
        st->owner.failed = true;
        return;
    }
    if (strcmp((const char *)st->owner.line, "PUBLIC_BOOTSTRAP_RAW_READY\r\n") == 0) {
        if (st->owner.ready) st->owner.failed = true;
        st->owner.ready = machine->con.ports[4].host_open && machine->con.ports[4].guest_open;
        st->owner.ready_epoch = epoch;
        st->owner.ready_device_epoch = device_epoch;
        st->owner.instance = instance;
    } else if (strcmp((const char *)st->owner.line, "PUBLIC_OWNER_HEALTH\r\n") == 0) {
        st->owner.health = true;
        st->owner.health_instance = instance;
        st->owner.health_epoch = epoch;
        st->owner.health_device_epoch = device_epoch;
    } else if (strcmp((const char *)st->owner.line, "PUBLIC_OWNER_NEXT\r\n") == 0) {
        st->owner.command_pending = true;
    } else if (strcmp((const char *)st->owner.line, "PUBLIC_OWNER_DONE\r\n") == 0) {
        st->owner.done = st->owner.child && mb_owner_bootstrap_current(st, instance, epoch, device_epoch);
    } else if (strcmp((const char *)st->owner.line,
        "PUBLIC_BOOTSTRAP_CHILD delivered32=1 eof=1 reaped=1 timely=1 exited=1 status=0\r\n") == 0) {
        st->owner.child = st->owner.delivered && mb_owner_bootstrap_current(st, instance, epoch, device_epoch);
    }
}

static void mb_owner_line(struct mb_state *st,const struct rvmachine *machine,
    uint64_t instance,uint32_t epoch,uint32_t device_epoch)
{
    if(st->owner.protected)mb_owner_protected_line(st,machine,instance,epoch,device_epoch);
    else mb_owner_public_line(st,machine,instance,epoch,device_epoch);
}
static void mb_owner_prompt(struct mb_state *st, uint8_t byte)
{
    /* FreeBSD -s asks for a shell before it can print its first prompt.
     * Observe only the fixed line prefix; input is sent between drives. */
    if (st->owner.command_step == 0 && st->owner.line_length == 19 &&
        memcmp(st->owner.line, "Enter full pathname", 19) == 0)
        st->owner.command_pending = true;
    if (st->owner.command_step == 1 && st->owner.line_length >= 2 &&
        st->owner.line[st->owner.line_length - 2] == '#' && byte == ' ')
        st->owner.command_pending = true;
}

static void mb_owner_console(void *context, const struct rvmachine *machine,
    uint64_t instance, const uint8_t *bytes, size_t n)
{
    struct mb_state *st = context;
    if (!machine || machine->conport_count != 5 || !instance) { st->owner.failed = true; return; }
    st->m = (struct rvmachine *)machine; /* borrowed until successful manager join */
    uint32_t epoch = machine->conports[4].generation;
    uint32_t device_epoch = machine->con.ports[4].generation;
    for (size_t i = 0; i < n; i++) {
        if (!st->owner.line_length) {
            st->owner.line_epoch = epoch;
            st->owner.line_device_epoch = device_epoch;
            st->owner.line_instance = instance;
        }
        if (st->owner.line_epoch != epoch || st->owner.line_device_epoch != device_epoch ||
            st->owner.line_instance != instance ||
            st->owner.line_length == sizeof(st->owner.line) - 1) {
            st->owner.failed = true;
            st->owner.ready = false;
            memory_cleanse(st->owner.line, sizeof(st->owner.line));
            st->owner.line_length = 0;
            return;
        }
        st->owner.line[st->owner.line_length++] = bytes[i];
        mb_owner_prompt(st, bytes[i]);
        if (bytes[i] != '\n') continue;
        st->owner.line[st->owner.line_length] = 0;
        mb_owner_line(st, machine, instance, epoch, device_epoch);
        memory_cleanse(st->owner.line, sizeof(st->owner.line));
        st->owner.line_length = 0;
    }
}

static bool mb_owner_receiver_current(void *context, const struct rvmachine *machine,
    uint64_t instance, uint32_t epoch)
{
    struct mb_state *st = context;
    return !st->owner.failed && !st->entropy_failed && st->owner.health &&
        st->early_given != 0 && st->owner.ready && st->m == machine &&
        st->owner.instance == instance && st->owner.health_instance == instance &&
        st->owner.health_epoch == epoch &&
        st->owner.health_device_epoch == machine->con.ports[4].generation &&
        st->owner.ready_epoch == epoch &&
        st->owner.ready_device_epoch == machine->con.ports[4].generation;
}

/* The local owner fixes the executable identity independently of the unsigned
 * CAS statement. Its evidence inventories remain opaque preserved bytes. */
static bool mb_owner_public_image_grant(void *context, const uint8_t root[32],
    const struct vcs_guest_image_observation *observation)
{
    struct mb_state *st = context;
    const struct mb_owner_profile *profile = st ? mb_owner_profile(st->owner.profile_revision) : NULL;
    uint8_t fixed[32];
    if (!profile || !st || !root || !st->owner.enabled || !st->accepted.public_observation ||
        st->owner.failed || st->entropy_failed ||
        memcmp(root, st->accepted.root, 32) != 0 ||
        !zcl_hex_decode_lower(profile->kernel, fixed, 32) ||
        memcmp(fixed, st->owner.authorized_kernel, 32) != 0) return false;
    return !observation || (observation->image.bytes == mb_owner_image_bytes(st) &&
        memcmp(observation->image_sha256, fixed, 32) == 0);
}

bool zcl_mb_owner_image_grant(void *context,const uint8_t root[32],
    const struct vcs_guest_image_observation *observation)
{
    struct mb_state *st=context;
    if(st && st->owner.protected)return mb_protected_image_grant(st,root,observation);
    return mb_owner_public_image_grant(context,root,observation);
}
static bool mb_owner_accepted_current(void *context, const uint8_t expected[32])
{
    struct mb_state *st = context;
    if (!st->owner.enabled || (!st->accepted.reader && !st->accepted.public_reader) ||
        memcmp(expected, st->owner.authorized_kernel, 32) != 0) return false;
    size_t produced = st->accepted.length;
    struct zcl_result result = (st->accepted.public_observation || st->accepted.protected_observation) ?
        guest_image_admission_current(st->accepted.public_reader) :
        package_lifecycle_declared_output_read_verified(
            st->accepted.reader, st->accepted.image, (size_t)st->accepted.capacity, &produced);
    if (!result.ok || produced != st->accepted.length) return false;
    uint8_t digest[32];
    struct sha256_ctx hash;
    sha256_init(&hash); sha256_write(&hash, st->accepted.image, produced);
    sha256_finalize(&hash, digest);
    return memcmp(digest, expected, 32) == 0;
}

static bool mb_owner_keyfile_current(void *context, const struct platform_private_file *file)
{
    struct mb_state *st = context;
    if (file != &st->owner.credential || !file->locked) return false;
    struct platform_positioned_file view = {.native = file->native};
    struct platform_positioned_file_snapshot current;
    return platform_positioned_file_is_current_user_only(&view) &&
        platform_positioned_file_snapshot(&view, &current) && current.size == 32 &&
        platform_positioned_file_snapshot_equal(&current, &st->owner.credential_snapshot);
}

static char *mb_owner_path_copy(const char *path)
{
    size_t n = strlen(path);
    if (!n || n >= 4096) return NULL;
    char *copy = zcl_malloc(n + 1, "PUBLIC owner retained path");
    if (copy) memcpy(copy, path, n + 1);
    return copy;
}

static bool mb_owner_volume_files(struct mb_state *st)
{
    char resolved[4096], parent[4096];
    if (st->owner.recover) {
        if (!platform_private_file_open_locked(st->owner.record_path, &st->owner.record) ||
            !platform_private_file_open_locked(st->owner.volume_path, &st->owner.volume)) return false;
    } else {
        if (!platform_private_path_absent(st->owner.record_path) ||
            !platform_private_path_absent(st->owner.volume_path) ||
            !platform_private_file_create_locked(st->owner.volume_path, &st->owner.volume)) return false;
        st->owner.mutated = true;
        if (!platform_private_file_truncate(&st->owner.volume, UINT64_C(16) << 20) ||
            !platform_private_file_flush(&st->owner.volume)) return false;
    }
    if (!st->owner.recover &&
        (!platform_private_destination_resolve(st->owner.volume_path,
            resolved, sizeof(resolved), parent, sizeof(parent)) ||
         !platform_private_parent_flush(parent))) return false;
    return true;
}

/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Called only after distinct exact protected image admission. Existing
 * credential metadata is checked first; plaintext read occurs later in
 * cached_configure after actual receiver readiness and durable reservation. */
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Native host provisioning requires initial/create-new-host admission.
 * The caller owns cleanup of the retained locked descriptor. Failed creation
 * or persistence leaves its path for reconciliation; never overwrite/retry.
 * Generated credential bytes are never logged or emitted as diagnostics. */
static bool mb_protected_credential_readback(struct mb_state *st,
    const uint8_t generated[32],uint8_t observed[32])
{
    struct platform_positioned_file view={.native=st->owner.credential.native};
    struct platform_positioned_file_snapshot before,after;
    if(!platform_positioned_file_is_private(&view)||
        !platform_positioned_file_is_current_user_only(&view)||
        !platform_positioned_file_snapshot(&view,&before)||before.size!=32||
        !platform_private_file_read_at(&st->owner.credential,observed,32,0)||
        !platform_positioned_file_snapshot(&view,&after)||
        !platform_positioned_file_snapshot_equal(&before,&after)||
        memcmp(generated,observed,32))return false;
    st->owner.credential_snapshot=after;
    return true;
}
static bool mb_protected_create_credential(struct mb_state *st)
{
    char resolved[4096], parent[4096];
    uint8_t generated[32] = {0}, observed[32] = {0};
    bool ok = false;
    if (!st || !st->owner.protected || st->owner.recover ||
        st->owner.credential.locked || !st->owner.credential_path) {
        LOG_WARN("guest.owner", "protected credential creation refused: invalid initial owner");
        return false;
    }
    if (!platform_private_destination_resolve(st->owner.credential_path,
            resolved, sizeof(resolved), parent, sizeof(parent)) ||
        !platform_private_path_absent(resolved)) {
        LOG_WARN("guest.owner", "protected credential creation refused: destination resolution or absence");
        goto done;
    }
    if (!rng_host_fill(generated, sizeof(generated))) {
        LOG_WARN("guest.owner", "protected credential creation refused: host entropy unavailable");
        goto done;
    }
    /* Mark uncertainty before create: its lock failure may leave a created
     * file even though the API returns false. No success is inferred. */
    st->owner.mutated = true;
    if (!platform_private_file_create_locked(resolved, &st->owner.credential)) {
        LOG_WARN("guest.owner", "protected credential creation refused: exclusive create/lock");
        goto done;
    }
    if (!platform_private_file_write_at(&st->owner.credential, generated, sizeof(generated), 0) ||
        !platform_private_file_authority_flush(&st->owner.credential) ||
        !platform_private_parent_flush(parent)) {
        LOG_WARN("guest.owner", "protected credential persistence uncertain; reconciliation required");
        goto done;
    }
    if (!mb_protected_credential_readback(st,generated,observed)) {
        LOG_WARN("guest.owner", "protected credential readback refused; reconciliation required");
        goto done;
    }
    ok = true;
done:
    memory_cleanse(generated, sizeof(generated));
    memory_cleanse(observed, sizeof(observed));
    return ok;
}
/* Preflight is metadata only and runs before RNG or any output creation.
 * It cannot lock an absent leaf; later O_EXCL/durable rails remain mandatory. */
static bool mb_protected_initial_outputs_absent(const struct mb_state *st)
{
    const struct mb_protected_owner *p=st->owner.protected;
    if(st->owner.recover)return !p->create_credential;
    const char *paths[]={st->owner.record_path,st->owner.volume_path,
        p->extension_path,p->reserve_stage_path,p->ready_stage_path};
    for(size_t i=0;i<sizeof paths/sizeof paths[0];i++){
        char resolved[4096],parent[4096];
        if(!platform_private_destination_resolve(paths[i],resolved,sizeof resolved,parent,sizeof parent)||
            !platform_private_path_absent(resolved))return false;
    }
    if(p->create_credential){
        char resolved[4096],parent[4096];
        return platform_private_destination_resolve(st->owner.credential_path,
            resolved,sizeof resolved,parent,sizeof parent)&&platform_private_path_absent(resolved);
    }
    return true;
}
static bool mb_protected_credential_open(struct mb_state *st)
{
    if(st->owner.protected->create_credential)
        return mb_protected_create_credential(st); /* No fallback/retry on uncertainty. */
    return platform_private_file_open_locked(st->owner.credential_path,&st->owner.credential);
}
static bool mb_protected_credential_files(struct mb_state *st)
{
    struct mb_protected_owner *p=st->owner.protected;
    if(!mb_protected_initial_outputs_absent(st))return false;
    p->owned_extension_path=mb_owner_path_copy(p->extension_path);
    p->owned_reserve_stage_path=mb_owner_path_copy(p->reserve_stage_path);
    p->owned_ready_stage_path=mb_owner_path_copy(p->ready_stage_path);
    if(!p->owned_extension_path || !p->owned_reserve_stage_path || !p->owned_ready_stage_path)return false;
    p->extension_path=p->owned_extension_path;
    p->reserve_stage_path=p->owned_reserve_stage_path;
    p->ready_stage_path=p->owned_ready_stage_path;
    st->owner.owned_volume_path=mb_owner_path_copy(st->owner.volume_path);
    st->owner.owned_record_path=mb_owner_path_copy(st->owner.record_path);
    st->owner.owned_credential_path=mb_owner_path_copy(st->owner.credential_path);
    if(!st->owner.owned_volume_path || !st->owner.owned_record_path ||
        !st->owner.owned_credential_path)return false;
    st->owner.volume_path=st->owner.owned_volume_path;
    st->owner.record_path=st->owner.owned_record_path;
    st->owner.credential_path=st->owner.owned_credential_path;
    if(!mb_protected_credential_open(st))return false;
    struct platform_positioned_file view={.native=st->owner.credential.native};
    if(!platform_positioned_file_is_private(&view) ||
        !platform_positioned_file_is_current_user_only(&view) ||
        !platform_positioned_file_snapshot(&view,&st->owner.credential_snapshot) ||
        st->owner.credential_snapshot.size!=32)return false;
    return mb_owner_volume_files(st);
}
static bool mb_owner_files(struct mb_state *st)
{
    if(st->owner.protected)return mb_protected_credential_files(st);
    st->owner.owned_volume_path = mb_owner_path_copy(st->owner.volume_path);
    st->owner.owned_record_path = mb_owner_path_copy(st->owner.record_path);
    st->owner.owned_credential_path = mb_owner_path_copy(st->owner.credential_path);
    if (!st->owner.owned_volume_path || !st->owner.owned_record_path ||
        !st->owner.owned_credential_path) return false;
    st->owner.volume_path = st->owner.owned_volume_path;
    st->owner.record_path = st->owner.owned_record_path;
    st->owner.credential_path = st->owner.owned_credential_path;
    if (!platform_private_path_absent(st->owner.credential_path)) return false;
    if (!mb_owner_volume_files(st)) return false;
    char resolved[4096], parent[4096];
    if (!platform_private_destination_resolve(st->owner.credential_path,
            resolved, sizeof(resolved), parent, sizeof(parent)) ||
        !platform_private_file_create_locked(resolved, &st->owner.credential)) return false;
    st->owner.mutated = true;
    uint8_t public_bytes[32];
    for (size_t i = 0; i < sizeof(public_bytes); i++) public_bytes[i] = (uint8_t)(i + 1);
    bool ok = platform_private_file_write_at(&st->owner.credential, public_bytes, sizeof(public_bytes), 0) &&
        platform_private_file_flush(&st->owner.credential) && platform_private_parent_flush(parent);
    memory_cleanse(public_bytes, sizeof(public_bytes));
    struct platform_positioned_file view = {.native = st->owner.credential.native};
    return ok && platform_positioned_file_snapshot(&view, &st->owner.credential_snapshot) &&
        mb_owner_keyfile_current(st, &st->owner.credential);
}

static bool mb_owner_input_room(const struct rvmachine *machine, size_t n)
{
    /* console_input broadcasts to two readers and can discard their oldest
     * bytes. Admit only between phases, without clearing either reader. */
    return machine && machine->firmware_in.count <= RVMACHINE_INPUT_MAX &&
        machine->serial_in.count <= RVMACHINE_INPUT_MAX &&
        n <= RVMACHINE_INPUT_MAX - machine->firmware_in.count &&
        n <= RVMACHINE_INPUT_MAX - machine->serial_in.count &&
        machine->serial_in.count == 0 && machine->uart.rx_count == 0;
}

#define MB_OWNER_V2_COMMAND_0 \
    "\n"
#define MB_OWNER_V2_COMMAND_1 \
    "v=$(sysctl -n kern.random.initial_seeding.bypass_before_seeding) && [ \"$v\" = 0 ]\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:1:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_2 \
    "v=$(sysctl -n kern.random.initial_seeding.read_random_bypassed_before_seeding) && [ \"$v\" = 0 ]\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:2:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_3 \
    "v=$(sysctl -n kern.random.initial_seeding.arc4random_bypassed_before_seeding) && [ \"$v\" = 0 ]\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:3:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_4 \
    "dd if=/dev/random of=/dev/null bs=1 count=1 2>/dev/null\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:4:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_HEALTH\\n'\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_5 \
    "geli init -B none -P -K /PUBLIC_BOOTSTRAP_LITERAL.key -a HMAC/SHA256 -e AES-XTS -l 256 -s 4096 /dev/vtbd0\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:5:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_6 \
    "/sbin/geli-bootstrap-public && [ -c /dev/vtbd0.eli ]\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:6:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_7 \
    "dd if=/dev/zero of=/dev/vtbd0.eli bs=4096 seek=2 count=2 conv=fsync &&\n" \
    "dd if=/dev/zero of=/dev/vtbd0.eli bs=4096 seek=15 count=3 conv=notrunc,fsync &&\n" \
    "printf '\\1207A\\n' &&\n" \
    "newfs -U /dev/vtbd0.eli &&\n" \
    "printf '\\1207B\\n' &&\n" \
    "mount -t ufs /dev/vtbd0.eli /z23/identity\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:7:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_8 \
    "/bin/chmod 0700 /z23/identity &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op:%u' /z23/identity) &&\n" \
    "[ \"$metadata\" = '40700:0' ]\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:8:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V3_COMMAND_6 \
    "/sbin/geli-bootstrap-public --public-initial-prepare && [ -c /dev/vtbd0.eli ]\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:6:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V3_COMMAND_7 \
    "newfs -U /dev/vtbd0.eli &&\n" \
    "printf '\\120UBLIC_V3_NEWFS_DONE\\n' &&\n" \
    "mount -t ufs /dev/vtbd0.eli /z23/identity\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:7:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_9 \
    "umask 077 &&\n" \
    "[ ! -e /z23/identity/ssh_host_ed25519_key ] && [ ! -L /z23/identity/ssh_host_ed25519_key ] &&\n" \
    "[ ! -e /z23/identity/ssh_host_ed25519_key.pub ] && [ ! -L /z23/identity/ssh_host_ed25519_key.pub ] &&\n" \
    "ssh-keygen -q -t ed25519 -N '' -C z23-fixture-host -f /z23/identity/ssh_host_ed25519_key </dev/null\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:9:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_10 \
    "metadata=$(/usr/bin/stat -f '%Op %u %l %z' /z23/identity/ssh_host_ed25519_key) &&\n" \
    "case \"$metadata\" in ''|*[!0-9' ']*) false;; *) set -- $metadata;; esac &&\n" \
    "[ \"$#\" = 4 ] && [ \"$1:$2:$3\" = '100600:0:1' ] && [ \"$4\" -gt 0 ] &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op:%u:%l:%z' /z23/identity/ssh_host_ed25519_key.pub) &&\n" \
    "[ \"$metadata\" = '100600:0:1:98' ]\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:10:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_11 \
    "umount /z23/identity &&\n" \
    "/sbin/geli-mounted-flush\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:11:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_12 \
    "mount -t ufs -o ro,noatime /dev/vtbd0.eli /z23/identity &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op:%u' /z23/identity) &&\n" \
    "[ \"$metadata\" = '40700:0' ] &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op %u %l %z' /z23/identity/ssh_host_ed25519_key) &&\n" \
    "case \"$metadata\" in ''|*[!0-9' ']*) false;; *) set -- $metadata;; esac &&\n" \
    "[ \"$#\" = 4 ] && [ \"$1:$2:$3\" = '100600:0:1' ] && [ \"$4\" -gt 0 ] &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op:%u:%l:%z' /z23/identity/ssh_host_ed25519_key.pub) &&\n" \
    "[ \"$metadata\" = '100600:0:1:98' ]\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:12:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_13 \
    "umask 077 &&\n" \
    "[ ! -e /PUBLIC_V2_DERIVED.pub ] && [ ! -L /PUBLIC_V2_DERIVED.pub ] &&\n" \
    "set -C &&\n" \
    "ssh-keygen -y -f /z23/identity/ssh_host_ed25519_key </dev/null >/PUBLIC_V2_DERIVED.pub &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op:%u:%l:%z' /PUBLIC_V2_DERIVED.pub) &&\n" \
    "[ \"$metadata\" = '100600:0:1:98' ]\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:13:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_14 \
    "IFS= read -r public_key </PUBLIC_V2_DERIVED.pub &&\n" \
    "printf '\\120UBLIC_V2_KEY:%s\\n' \"$public_key\"\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:14:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_15 \
    "ssh-keygen -lf /PUBLIC_V2_DERIVED.pub -E sha256\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:15:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n"
#define MB_OWNER_V2_COMMAND_16 \
    "umount /z23/identity &&\n" \
    "/sbin/geli-mounted-flush\n" \
    "rc=$?\n" \
    "printf '\\120UBLIC_V2_RC:16:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_DONE\\n'\n"
static const char *const mb_owner_v2_commands[17] = {
    MB_OWNER_V2_COMMAND_0,
    MB_OWNER_V2_COMMAND_1,
    MB_OWNER_V2_COMMAND_2,
    MB_OWNER_V2_COMMAND_3,
    MB_OWNER_V2_COMMAND_4,
    MB_OWNER_V2_COMMAND_5,
    MB_OWNER_V2_COMMAND_6,
    MB_OWNER_V2_COMMAND_7,
    MB_OWNER_V2_COMMAND_8,
    MB_OWNER_V2_COMMAND_9,
    MB_OWNER_V2_COMMAND_10,
    MB_OWNER_V2_COMMAND_11,
    MB_OWNER_V2_COMMAND_12,
    MB_OWNER_V2_COMMAND_13,
    MB_OWNER_V2_COMMAND_14,
    MB_OWNER_V2_COMMAND_15,
    MB_OWNER_V2_COMMAND_16
};
static const char mb_owner_v2_recover5[] = "true\nrc=$?\nprintf '\\120UBLIC_V2_RC:5:%u\\n' \"$rc\"\n[ \"$rc\" = 0 ] && printf '\\120UBLIC_OWNER_NEXT\\n'\n";
enum {
    MB_OWNER_V2_INITIAL_BYTES = sizeof(MB_OWNER_V2_COMMAND_0) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_1) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_2) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_3) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_4) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_5) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_6) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_7) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_8) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_9) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_10) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_11) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_12) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_13) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_14) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_15) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_16) - 1,
    MB_OWNER_V2_RECOVER_BYTES = sizeof(MB_OWNER_V2_COMMAND_0) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_1) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_2) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_3) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_4) - 1 +
        sizeof(mb_owner_v2_recover5) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_6) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_12) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_13) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_14) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_15) - 1 +
        sizeof(MB_OWNER_V2_COMMAND_16) - 1
};
_Static_assert(MB_OWNER_V2_INITIAL_BYTES <= RVMACHINE_INPUT_MAX, "initial broadcast queue capacity");
_Static_assert(MB_OWNER_V2_RECOVER_BYTES <= RVMACHINE_INPUT_MAX, "recovery broadcast queue capacity");
enum {
    MB_OWNER_V3_INITIAL_BYTES = MB_OWNER_V2_INITIAL_BYTES -
        (sizeof(MB_OWNER_V2_COMMAND_6) - 1) - (sizeof(MB_OWNER_V2_COMMAND_7) - 1) +
        (sizeof(MB_OWNER_V3_COMMAND_6) - 1) + (sizeof(MB_OWNER_V3_COMMAND_7) - 1)
};
_Static_assert(MB_OWNER_V3_INITIAL_BYTES <= RVMACHINE_INPUT_MAX, "prepared initial broadcast queue capacity");

#define MB_OWNER_NEXT "printf '\\120\\125\\102\\114\\111\\103\\137\\117\\127\\116\\105\\122\\137\\116\\105\\130\\124\\n'\n"
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier:Apache-2.0 */
/* Commands for the distinct admitted protected owner.
 * Never select these through a PUBLIC profile or policy.
 * Caller must bind current typed mode and exact protected image/helper/session.
 * This is command data, not a parallel manager or authority implementation. */
static const char pc_initial5[] =
    "true\n"
    "rc=$?\n"
    "printf 'PROTECTED_V1_RC:5:%u\\n' \"$rc\"\n"
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n";
static const char pc_initial6[] =
    "/sbin/geli-protected-consumer --protected-initial-v1 && [ -c /dev/vtbd0.eli ]\n"
    "rc=$?\n"
    "printf 'PROTECTED_V1_RC:6:%u\\n' \"$rc\"\n"
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n";
static const char pc_recover6[] =
    "/sbin/geli-protected-consumer --protected-recover-v1 && [ -c /dev/vtbd0.eli ]\n"
    "rc=$?\n"
    "printf 'PROTECTED_V1_RC:6:%u\\n' \"$rc\"\n"
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n";
static const char pc_initial7[] =
    /* Same source-qualified20KiB offsets/two checkedflushes. Consumer194b
     * does NOT contain preparation; never borrow PUBLIC_PREPARED20K credit. */
    "dd if=/dev/zero of=/dev/vtbd0.eli bs=4096 seek=2 count=2 conv=fsync &&\n"
    "dd if=/dev/zero of=/dev/vtbd0.eli bs=4096 seek=15 count=3 conv=notrunc,fsync &&\n"
    "newfs -U /dev/vtbd0.eli &&\n"
    "printf 'PROTECTED_V1_NEWFS_DONE\\n' &&\n"
    "mount -t ufs /dev/vtbd0.eli /z23/identity\n"
    "rc=$?\n"
    "printf 'PROTECTED_V1_RC:7:%u\\n' \"$rc\"\n"
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n";
/* Existing owned commandflow must choose initial7 ONLY INITIAL; RECOVER6
 * success jumps12, skips7..11. Identity/read/unmount/flush steps13..16 need
 * matching distinct grammar and existing retained-key/record verification.
 * Entropy steps0..4 and final readiness still require actual current tuple.
 * Literal printf markers echo under shell: proposed parser must refuse loneLF
 * or wrongprefix, bind CRLF/currentcommand/instance/bothepochs and unique lines.
 * ReceiverREADY/ATTACHED/RC6 alone cannot authorize provider or prove child0:
 * distinct V3 child-proof grammar must bind INITIALinit+attach, RECOVER
 * attachonly, source2df/binary194b/currenttuple beforeRC6. */

#define MB_PROTECTED_COMMAND_5 pc_initial5
#define MB_PROTECTED_COMMAND_6 pc_initial6
#define MB_PROTECTED_COMMAND_7 pc_initial7
#define MB_PROTECTED_COMMAND_0 \
    "\n"
#define MB_PROTECTED_COMMAND_1 \
    "v=$(sysctl -n kern.random.initial_seeding.bypass_before_seeding) && [ \"$v\" = 0 ]\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:1:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_2 \
    "v=$(sysctl -n kern.random.initial_seeding.read_random_bypassed_before_seeding) && [ \"$v\" = 0 ]\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:2:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_3 \
    "v=$(sysctl -n kern.random.initial_seeding.arc4random_bypassed_before_seeding) && [ \"$v\" = 0 ]\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:3:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_4 \
    "dd if=/dev/random of=/dev/null bs=1 count=1 2>/dev/null\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:4:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_HEALTH\\n'\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_8 \
    "/bin/chmod 0700 /z23/identity &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op:%u' /z23/identity) &&\n" \
    "[ \"$metadata\" = '40700:0' ]\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:8:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_9 \
    "umask 077 &&\n" \
    "[ ! -e /z23/identity/ssh_host_ed25519_key ] && [ ! -L /z23/identity/ssh_host_ed25519_key ] &&\n" \
    "[ ! -e /z23/identity/ssh_host_ed25519_key.pub ] && [ ! -L /z23/identity/ssh_host_ed25519_key.pub ] &&\n" \
    "ssh-keygen -q -t ed25519 -N '' -C z23-protected-host -f /z23/identity/ssh_host_ed25519_key </dev/null\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:9:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_10 \
    "metadata=$(/usr/bin/stat -f '%Op %u %l %z' /z23/identity/ssh_host_ed25519_key) &&\n" \
    "case \"$metadata\" in ''|*[!0-9' ']*) false;; *) set -- $metadata;; esac &&\n" \
    "[ \"$#\" = 4 ] && [ \"$1:$2:$3\" = '100600:0:1' ] && [ \"$4\" -gt 0 ] &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op:%u:%l:%z' /z23/identity/ssh_host_ed25519_key.pub) &&\n" \
    "[ \"$metadata\" = '100600:0:1:100' ]\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:10:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_11 \
    "umount /z23/identity &&\n" \
    "/sbin/geli-mounted-flush\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:11:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_12 \
    "mount -t ufs -o ro,noatime /dev/vtbd0.eli /z23/identity &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op:%u' /z23/identity) &&\n" \
    "[ \"$metadata\" = '40700:0' ] &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op %u %l %z' /z23/identity/ssh_host_ed25519_key) &&\n" \
    "case \"$metadata\" in ''|*[!0-9' ']*) false;; *) set -- $metadata;; esac &&\n" \
    "[ \"$#\" = 4 ] && [ \"$1:$2:$3\" = '100600:0:1' ] && [ \"$4\" -gt 0 ] &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op:%u:%l:%z' /z23/identity/ssh_host_ed25519_key.pub) &&\n" \
    "[ \"$metadata\" = '100600:0:1:100' ]\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:12:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_13 \
    "umask 077 &&\n" \
    "[ ! -e /PROTECTED_V1_DERIVED.pub ] && [ ! -L /PROTECTED_V1_DERIVED.pub ] &&\n" \
    "set -C &&\n" \
    "ssh-keygen -y -f /z23/identity/ssh_host_ed25519_key </dev/null >/PROTECTED_V1_DERIVED.pub &&\n" \
    "metadata=$(/usr/bin/stat -f '%Op:%u:%l:%z' /PROTECTED_V1_DERIVED.pub) &&\n" \
    "[ \"$metadata\" = '100600:0:1:100' ]\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:13:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_14 \
    "IFS= read -r public_key </PROTECTED_V1_DERIVED.pub &&\n" \
    "printf 'PROTECTED_V1_KEY:%s\\n' \"$public_key\"\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:14:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_15 \
    "ssh-keygen -lf /PROTECTED_V1_DERIVED.pub -E sha256\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:15:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_NEXT\\n'\n"
#define MB_PROTECTED_COMMAND_16 \
    "umount /z23/identity &&\n" \
    "/sbin/geli-mounted-flush\n" \
    "rc=$?\n" \
    "printf 'PROTECTED_V1_RC:16:%u\\n' \"$rc\"\n" \
    "[ \"$rc\" = 0 ] && printf 'PROTECTED_V1_DONE\\n'\n"
static const char *const mb_protected_commands[17] = {
    MB_PROTECTED_COMMAND_0,
    MB_PROTECTED_COMMAND_1,
    MB_PROTECTED_COMMAND_2,
    MB_PROTECTED_COMMAND_3,
    MB_PROTECTED_COMMAND_4,
    MB_PROTECTED_COMMAND_5,
    MB_PROTECTED_COMMAND_6,
    MB_PROTECTED_COMMAND_7,
    MB_PROTECTED_COMMAND_8,
    MB_PROTECTED_COMMAND_9,
    MB_PROTECTED_COMMAND_10,
    MB_PROTECTED_COMMAND_11,
    MB_PROTECTED_COMMAND_12,
    MB_PROTECTED_COMMAND_13,
    MB_PROTECTED_COMMAND_14,
    MB_PROTECTED_COMMAND_15,
    MB_PROTECTED_COMMAND_16
};
static const char *mb_protected_command_text(const struct mb_state *st,size_t *step)
{
        if(st->owner.recover && *step==7)*step=12;
        if(*step>=17)return NULL;
        if(*step==6)return st->owner.recover?pc_recover6:pc_initial6;
        return mb_protected_commands[*step];
}
static const char *mb_owner_public_command_text(const struct mb_state *st,size_t *step)
{
    static const char *const commands[] = {
        "\n", /* Accept /bin/sh at the observed single-user shell entry. */
        "[ \"$(sysctl -n kern.random.initial_seeding.bypass_before_seeding)\" = 0 ] &&\n" MB_OWNER_NEXT,
        "[ \"$(sysctl -n kern.random.initial_seeding.read_random_bypassed_before_seeding)\" = 0 ] &&\n" MB_OWNER_NEXT,
        "[ \"$(sysctl -n kern.random.initial_seeding.arc4random_bypassed_before_seeding)\" = 0 ] &&\n" MB_OWNER_NEXT,
        "dd if=/dev/random of=/dev/null bs=1 count=1 2>/dev/null &&\n"
        "printf '\\120\\125\\102\\114\\111\\103\\137\\117\\127\\116\\105\\122\\137\\110\\105\\101\\114\\124\\110\\n' &&\n" MB_OWNER_NEXT,
        "geli init -B none -P -K /PUBLIC_BOOTSTRAP_LITERAL.key -a HMAC/SHA256 -e AES-XTS -l 256 -s 4096 /dev/vtbd0 &&\n" MB_OWNER_NEXT,
        "/sbin/geli-bootstrap-public && geli list vtbd0.eli >/dev/null &&\n"
        "printf '\\120\\125\\102\\114\\111\\103\\137\\117\\127\\116\\105\\122\\137\\104\\117\\116\\105\\n'\n"
    };
    if (mb_owner_typed_profile(st)) {
        if (st->owner.recover && *step == 7) *step = 12;
        if (*step >= sizeof(mb_owner_v2_commands) / sizeof(mb_owner_v2_commands[0])) return NULL;
        if (mb_owner_prepared_profile(st) && !st->owner.recover) {
            if (*step == 6) return MB_OWNER_V3_COMMAND_6;
            if (*step == 7) return MB_OWNER_V3_COMMAND_7;
        }
        return st->owner.recover && *step == 5 ? mb_owner_v2_recover5 : mb_owner_v2_commands[*step];
    }
    if (*step >= sizeof(commands) / sizeof(commands[0])) return NULL;
    return st->owner.recover && *step == 5 ? MB_OWNER_NEXT : commands[*step];
}
static const char *mb_owner_command_text(const struct mb_state *st,size_t *step)
{
    return st->owner.protected?mb_protected_command_text(st,step):mb_owner_public_command_text(st,step);
}
#undef MB_OWNER_NEXT

static bool mb_owner_command_lines(const char *text, size_t n)
{
    size_t line = 0;
    for (size_t i = 0; i < n; i++) {
        if (text[i] == '\n') line = 0;
        else if (++line >= 256) return false;
    }
    return true;
}
static bool mb_owner_command_stage(struct mb_state *st, size_t step,
    struct mb_command_observation *staged)
{
    *staged = st->owner.command;
    if (!mb_owner_typed_profile(st) || step == 0) return true;
    uint64_t instance = mesh_guest_service_manager_instance(st->owner.manager);
    uint32_t epoch = st->m->conports[4].generation;
    uint32_t device_epoch = st->m->con.ports[4].generation;
    if (step >= 7 && !mb_owner_identity_current(st, instance, epoch, device_epoch)) return false;
    return mb_command_begin(staged, (unsigned)step, instance, epoch, device_epoch);
}
static bool mb_owner_command(struct mb_state *st)
{
    if (!st->owner.command_pending) return true;
    if (st->owner.failed || st->entropy_failed) return false;
    size_t step = st->owner.command_step;
    const char *text = mb_owner_command_text(st, &step);
    if (!text) return false;
    size_t n = strlen(text);
    struct mb_command_observation staged;
    if (!mb_owner_command_lines(text, n) || !mb_owner_input_room(st->m, n) ||
        !mb_owner_command_stage(st, step, &staged) ||
        rvmachine_console_input(st->m, (const uint8_t *)text, n) != n) return false;
    if (step == 6 && mb_owner_prepared_profile(st)) st->owner.prepared20k_seen = false;
    if (step == 7 && mb_owner_prepared_profile(st)) st->owner.v3_newfs_done = false;
    st->owner.command = staged;
    st->owner.command_pending = false;
    st->owner.command_step = step + 1;
    return true;
}

static bool mb_owner_deny_peer(void *context, const uint8_t peer[32],
    const uint8_t *hello, size_t hello_n, uint8_t *reply, size_t capacity,
    size_t *written, uint32_t *slot, uint32_t *role)
{
    (void)context; (void)peer; (void)hello; (void)hello_n;
    (void)reply; (void)capacity; (void)slot; (void)role;
    if (written) *written = 0;
    return false; /* This PUBLIC local fixture grants no peer T/P binding. */
}

static void mb_owner_label_digest(const char *label, uint8_t out[32])
{
    struct sha256_ctx hash;
    sha256_init(&hash); sha256_write(&hash, (const uint8_t *)label, strlen(label));
    sha256_finalize(&hash, out);
}

/* Copyright2026 RhettCreighton; SPDX-License-Identifier:Apache-2.0 */
/* Inert functions in existing nativeowner; reuse256-byte console reducer and
 * command_current. PUBLIC readiness/delivery/child flags NEVER supply credit. */
static bool mb_protected_helper_bound(const struct mb_protected_child_observation *p)
{
    static const uint8_t helper[32]={
        0x19,0x4b,0xd9,0xc2,0x97,0x7d,0xca,0xb3,0xc3,0x40,0x47,0x2d,0x10,0xf8,0x29,0x1c,
        0x26,0x6b,0xdc,0x6f,0xff,0x46,0x3d,0x02,0x23,0xf1,0x30,0x88,0x6c,0x39,0x6c,0x4e};
    return p&&p->consumer==MB_CHILD_PROTECTED_V1&&p->image_bound&&
        !memcmp(p->helper_sha256,helper,sizeof helper);
}
static bool mb_protected_phase6_current(const struct mb_state *st,
    const struct mb_protected_child_observation *p,uint64_t instance,
    uint32_t host_epoch,uint32_t device_epoch)
{
    return mb_protected_helper_bound(p)&&!st->owner.failed&&st->owner.command_step==7&&
        !st->owner.command.rc_seen&&mb_command_current(&st->owner.command,6,instance,host_epoch,device_epoch);
}
static bool mb_protected_host_port_current(const struct rvmachine *m,uint32_t host_epoch,uint32_t device_epoch)
{
    const struct rvmachine_conport *port=&m->conports[4];
    return port->generation==host_epoch&&port->seen_generation==device_epoch&&
        port->private_keyfile&&!port->private_failed&&!port->retired;
}
static bool mb_protected_port_identity(const struct rvmachine *m,uint32_t host_epoch,uint32_t device_epoch)
{
    static const char name[]="z23.protected.bootstrap.v1";
    if(!m||m->conport_count!=5||m->conport_fault||!host_epoch||!device_epoch)return false;
    const struct rvvirtio_console_port *port=&m->con.ports[4];
    return mb_protected_host_port_current(m,host_epoch,device_epoch)&&port->generation==device_epoch&&
        port->host_open&&port->name_len==sizeof(name)-1&&
        !memcmp(port->name,name,sizeof(name));
}
static bool mb_protected_device_live(const struct rvmachine *m)
{
    uint32_t status=m->con.dev.status;
    return (status&RVVIRTIO_STATUS_DRIVER_OK)&&!(status&(RVVIRTIO_STATUS_NEEDS_RESET|RVVIRTIO_STATUS_FAILED));
}
static bool mb_protected_ready_port(const struct rvmachine *m,uint32_t host,uint32_t device)
{return mb_protected_port_identity(m,host,device)&&mb_protected_device_live(m)&&m->con.ports[4].guest_open&&!m->conports[4].private_sealed;}
static bool mb_protected_post_port(const struct rvmachine *m,uint32_t host,uint32_t device)
{return mb_protected_port_identity(m,host,device)&&mb_protected_device_live(m)&&m->conports[4].private_sealed&&m->conports[4].count==0;}
static bool mb_protected_ready_accept(const struct mb_state *st,
    struct mb_protected_child_observation *p,const struct rvmachine *m,
    uint64_t instance,uint32_t host_epoch,uint32_t device_epoch)
{
    if(m!=st->m||!mb_protected_phase6_current(st,p,instance,host_epoch,device_epoch)||
        !mb_protected_ready_port(m,host_epoch,device_epoch))return false;
    if(!instance||p->ready||p->delivered)return false;
    p->ready=true;p->ready_machine=m;p->ready_instance=instance;
    p->ready_host_epoch=host_epoch;p->ready_device_epoch=device_epoch;return true;
}
static bool mb_protected_ready_current(const struct mb_protected_child_observation *p,
    const struct rvmachine *m,uint64_t instance,uint32_t host_epoch,uint32_t device_epoch)
{
    return p->ready&&p->ready_machine==m&&p->ready_instance==instance&&
        p->ready_host_epoch==host_epoch&&p->ready_device_epoch==device_epoch;
}
static bool mb_protected_delivery_current(const struct mb_protected_child_observation *p,
    uint64_t instance,uint32_t host_epoch,uint32_t device_epoch)
{
    return p->delivered&&p->delivery_instance==instance&&
        p->delivery_host_epoch==host_epoch&&p->delivery_device_epoch==device_epoch;
}
static bool mb_protected_child_current(const struct mb_state *st,
    const struct mb_protected_child_observation *p,const struct rvmachine *m,
    uint64_t instance,uint32_t host_epoch,uint32_t device_epoch)
{
    return m==st->m&&mb_protected_phase6_current(st,p,instance,host_epoch,device_epoch)&&
        mb_protected_post_port(m,host_epoch,device_epoch)&&
        mb_protected_ready_current(p,m,instance,host_epoch,device_epoch)&&
        mb_protected_delivery_current(p,instance,host_epoch,device_epoch);
}
static bool mb_protected_child_complete(const struct mb_state *st,
    const struct mb_protected_child_observation *p)
{
    return p->attach_seen&&(st->owner.recover?!p->init_seen:p->init_seen);
}
static bool mb_protected_proof_prefix(const uint8_t *line,size_t n)
{
    static const char *const stems[]={"PROTECTED_V1_RECEIVER_READY","PROTECTED_V1_CHILD","PROTECTED_V1_ATTACH_EXACT32","PUBLIC_"};
    for(size_t i=0;i<sizeof stems/sizeof stems[0];i++){size_t len=strlen(stems[i]);if(n>=len&&!memcmp(line,stems[i],len))return true;}
    return false;
}
enum mb_protected_proof_kind { MB_PP_NONE,MB_PP_BAD,MB_PP_READY,MB_PP_INIT,MB_PP_ATTACH,MB_PP_FINAL,MB_PP_RC6,MB_PP_NEXT };
static enum mb_protected_proof_kind mb_protected_proof_kind(const uint8_t *line,size_t n,unsigned phase)
{
    static const char next[]="PROTECTED_V1_NEXT\r\n";
    static const struct {const char *text;enum mb_protected_proof_kind kind;} rows[]={
        {"PROTECTED_V1_RECEIVER_READY\r\n",MB_PP_READY},
        {"PROTECTED_V1_CHILD phase=init delivered32=1 eof=1 reaped=1 timely=1 exited=1 status=0\r\n",MB_PP_INIT},
        {"PROTECTED_V1_CHILD phase=attach delivered32=1 eof=1 reaped=1 timely=1 exited=1 status=0\r\n",MB_PP_ATTACH},
        {"PROTECTED_V1_ATTACH_EXACT32\r\n",MB_PP_FINAL},
        {"PROTECTED_V1_RC:6:0\r\n",MB_PP_RC6}};
    for(size_t i=0;i<sizeof rows/sizeof rows[0];i++){
        size_t length=strlen(rows[i].text);
        if(n==length&&!memcmp(line,rows[i].text,length))return rows[i].kind;
    }
    if(phase==6&&n==sizeof(next)-1&&!memcmp(line,next,sizeof(next)-1))return MB_PP_NEXT;
    if(n>=17&&!memcmp(line,"PROTECTED_V1_RC:6:",17))return MB_PP_BAD;
    if(phase==6&&n>=17&&!memcmp(line,"PROTECTED_V1_NEXT",17))return MB_PP_BAD;
    if(mb_protected_proof_prefix(line,n))return MB_PP_BAD;
    return MB_PP_NONE; /* Echo/wrongprefix supplies no observation. */
}
static bool mb_protected_init_accept(const struct mb_state *st,struct mb_protected_child_observation *p)
{
    if(st->owner.recover||p->init_seen||p->attach_seen||p->attached_seen)return false;
    p->init_seen=true;return true;
}
static bool mb_protected_attach_accept(const struct mb_state *st,struct mb_protected_child_observation *p)
{
    if(p->attach_seen||p->attached_seen||(!st->owner.recover&&!p->init_seen))return false;
    p->attach_seen=true;return true;
}
static bool mb_protected_final_accept(const struct mb_state *st,struct mb_protected_child_observation *p)
{
    if(p->attached_seen||!mb_protected_child_complete(st,p))return false;
    p->attached_seen=true;p->child=true;return true;
}
static bool mb_protected_rc6_stage(const struct mb_state *st,struct mb_protected_child_observation *p)
{if(p->rc6_pending||!p->attached_seen||!p->child||!mb_protected_child_complete(st,p))return false;p->rc6_pending=true;return true;}
static bool mb_protected_next_stage(struct mb_protected_child_observation *p)
{if(!p->rc6_pending||p->next_pending)return false;p->next_pending=true;return true;}
static bool mb_owner_protected_child_line(struct mb_state *st,
    struct mb_protected_child_observation *p,const struct rvmachine *m,
    uint64_t instance,uint32_t host_epoch,uint32_t device_epoch)
{
    enum mb_protected_proof_kind kind=mb_protected_proof_kind(st->owner.line,st->owner.line_length,st->owner.command.phase);
    if(kind==MB_PP_NONE)return false;
    bool ok=false;
    if(kind==MB_PP_READY)ok=mb_protected_ready_accept(st,p,m,instance,host_epoch,device_epoch);
    else if(mb_protected_child_current(st,p,m,instance,host_epoch,device_epoch)){
        switch(kind){
        case MB_PP_INIT:ok=mb_protected_init_accept(st,p);break;
        case MB_PP_ATTACH:ok=mb_protected_attach_accept(st,p);break;
        case MB_PP_FINAL:ok=mb_protected_final_accept(st,p);break;
        case MB_PP_RC6:ok=mb_protected_rc6_stage(st,p);break;
        case MB_PP_NEXT:ok=mb_protected_next_stage(p);break;
        default:break;
        }
    }
    if(!ok)st->owner.failed=true;
    return true;
}
static bool mb_protected_finished_command(const struct mb_state *st,uint64_t instance,
    uint32_t host_epoch,uint32_t device_epoch)
{
    return mb_command_current(&st->owner.command,6,instance,host_epoch,device_epoch)&&
        st->owner.command.rc_seen&&st->owner.command.next_seen;
}
static bool mb_owner_protected_rc6_ready(const struct mb_state *st,
    const struct mb_protected_child_observation *p,const struct rvmachine *m,
    uint64_t instance,uint32_t host_epoch,uint32_t device_epoch)
{
    return p->phase6_accepted&&p->consumed_verified&&p->child&&p->attached_seen&&
        mb_protected_child_complete(st,p)&&mb_protected_helper_bound(p)&&!st->owner.failed&&
        m==st->m&&mb_protected_post_port(m,host_epoch,device_epoch)&&
        mb_protected_ready_current(p,m,instance,host_epoch,device_epoch)&&
        mb_protected_delivery_current(p,instance,host_epoch,device_epoch)&&
        mb_protected_finished_command(st,instance,host_epoch,device_epoch);
}
static bool mb_protected_finish_refuse(struct mb_state *st)
{st->owner.failed=true;return false;}
static bool mb_owner_protected_phase6_finish(struct mb_state *st,
    struct mb_protected_child_observation *p,struct rvmachine *m,
    uint64_t instance,uint32_t host_epoch,uint32_t device_epoch)
{
    /* Called ONLY at returned-drive owner boundary, before next enqueue.
     * Console only stages proof/RC/NEXT; it never queries mutable consumption. */
    if(st->owner.failed)return false;
    if(p->phase6_accepted){
        if(!mb_owner_protected_rc6_ready(st,p,m,instance,host_epoch,device_epoch))return mb_protected_finish_refuse(st);
        return true;
    }
    if(!p->rc6_pending&&!p->next_pending)return true;
    if(!mb_protected_child_current(st,p,m,instance,host_epoch,device_epoch))return mb_protected_finish_refuse(st);
    if(!p->rc6_pending||!p->next_pending)return true;
    if(m->con.busy)return mb_protected_finish_refuse(st);
    size_t consumed=rvmachine_conport_consumed(m,4); /* Actual bounded fresh query. */
    if(consumed!=32||!mb_protected_post_port(m,host_epoch,device_epoch))return mb_protected_finish_refuse(st);
    p->consumed_verified=true;p->phase6_accepted=true;
    st->owner.command.rc_seen=true;st->owner.command.next_seen=true;st->owner.command_pending=true;
    return true;
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
static bool mb_protected_identity_current(const struct mb_state *st,uint64_t instance,
    uint32_t host,uint32_t device)
{
    const struct mb_protected_owner *p=st->owner.protected;
    return p && !p->terminal && !st->owner.failed && !st->entropy_failed && p->health &&
        p->health_instance==instance && p->health_host_epoch==host && p->health_device_epoch==device &&
        p->proof.phase6_accepted && p->proof.consumed_verified && p->proof.child &&
        mb_protected_ready_current(&p->proof,st->m,instance,host,device) &&
        mb_protected_delivery_current(&p->proof,instance,host,device) &&
        mb_protected_post_port(st->m,host,device);
}
static bool mb_protected_receiver_current(void *context,const struct rvmachine *machine,
    uint64_t instance,uint32_t host)
{
    struct mb_state *st=context;
    const struct mb_protected_owner *p=st->owner.protected;
    return p && !p->terminal && !st->owner.failed && !st->entropy_failed && p->health &&
        st->early_given && machine==st->m && p->health_instance==instance &&
        p->health_host_epoch==host && p->health_device_epoch==machine->con.ports[4].generation &&
        mb_protected_ready_current(&p->proof,machine,instance,host,machine->con.ports[4].generation);
}
static bool mb_protected_rc(const uint8_t *line,size_t n,unsigned *phase,unsigned *rc)
{
    static const char prefix[]="PROTECTED_V1_RC:";
    size_t start=sizeof prefix-1,colon=start;
    if(n<start+5 || n>start+8 || memcmp(line,prefix,start) ||
        line[n-2]!='\r' || line[n-1]!='\n')return false;
    while(colon<n-2 && line[colon]!=':')colon++;
    return colon<n-2 && mb_command_decimal(line+start,colon-start,16,phase) &&
        *phase && mb_command_decimal(line+colon+1,n-colon-3,255,rc);
}
static bool mb_protected_identity_line(struct mb_state *st,uint64_t instance,
    uint32_t host,uint32_t device)
{
    const uint8_t *line=st->owner.line;size_t n=st->owner.line_length;
    if(n>=17 && !memcmp(line,"PROTECTED_V1_KEY:",17)){
        if(!mb_protected_identity_current(st,instance,host,device) ||
            st->owner.command_step!=15 || st->owner.public_key_seen ||
            !mb_owner_wire_line(line,n,&st->owner.identity,"PROTECTED_V1_KEY:ssh-ed25519 ",
                " z23-protected-host\r\n"))st->owner.failed=true;
        else st->owner.public_key_seen=true;
        return true;
    }
    if(n>=11 && !memcmp(line,"256 SHA256:",11)){
        uint8_t observed[32];
        if(!mb_protected_identity_current(st,instance,host,device) ||
            st->owner.command_step!=16 || !st->owner.public_key_seen || st->owner.fingerprint_seen ||
            !mb_owner_fingerprint_exact_line(line,n,st->owner.identity.fingerprint,observed,
                " z23-protected-host (ED25519)\r\n"))st->owner.failed=true;
        else st->owner.fingerprint_seen=true;
        return true;
    }
    return false;
}
static bool mb_protected_accept_rc(struct mb_state *st,uint64_t instance,
    uint32_t host,uint32_t device)
{
    const uint8_t *line=st->owner.line;size_t n=st->owner.line_length;
    unsigned phase=0,rc=0;
        if(!mb_protected_rc(line,n,&phase,&rc) || rc || st->owner.command.rc_seen ||
            !mb_command_current(&st->owner.command,phase,instance,host,device))return false;
        if((phase==14 && !st->owner.public_key_seen) || (phase==15 && !st->owner.fingerprint_seen))return false;
        if(phase==7 && !st->owner.recover && !st->owner.protected->newfs_done)return false;
        st->owner.command.rc_seen=true;return true;
}
static bool mb_protected_accept_next(struct mb_state *st,uint64_t instance,
    uint32_t host,uint32_t device)
{
        if(!st->owner.command.rc_seen || st->owner.command.next_seen || st->owner.command.phase==16 ||
            !mb_command_current(&st->owner.command,st->owner.command.phase,instance,host,device))return false;
        st->owner.command.next_seen=true;st->owner.command_pending=true;return true;
}
static bool mb_protected_command_line(struct mb_state *st,uint64_t instance,
    uint32_t host,uint32_t device)
{
    const uint8_t *line=st->owner.line;size_t n=st->owner.line_length;
    if(n>=16 && !memcmp(line,"PROTECTED_V1_RC:",16))return mb_protected_accept_rc(st,instance,host,device);
    if(!strcmp((const char *)line,"PROTECTED_V1_NEXT\r\n"))return mb_protected_accept_next(st,instance,host,device);
    if(!strcmp((const char *)line,"PROTECTED_V1_DONE\r\n"))
        return mb_protected_identity_current(st,instance,host,device) &&
            mb_command_accept_done(&st->owner.command,st->owner.public_key_seen,
                st->owner.fingerprint_seen,st->owner.protected->proof.child,&st->owner.done);
    return false;
}
static void mb_protected_health_line(struct mb_state *st,uint64_t instance,uint32_t host,uint32_t device)
{
    struct mb_protected_owner *p=st->owner.protected;
        if(p->health || !st->owner.command.rc_seen ||
            !mb_command_current(&st->owner.command,4,instance,host,device))st->owner.failed=true;
        else {p->health=true;p->health_instance=instance;p->health_host_epoch=host;p->health_device_epoch=device;}
}
static void mb_protected_newfs_line(struct mb_state *st,uint64_t instance,uint32_t host,uint32_t device)
{
    struct mb_protected_owner *p=st->owner.protected;
        if(p->newfs_done || st->owner.recover ||
            !mb_protected_identity_current(st,instance,host,device) ||
            !mb_command_current(&st->owner.command,7,instance,host,device))st->owner.failed=true;
        else p->newfs_done=true;
}
static void mb_owner_protected_line(struct mb_state *st,const struct rvmachine *machine,
    uint64_t instance,uint32_t host,uint32_t device)
{
    struct mb_protected_owner *p=st->owner.protected;
    if(mb_owner_protected_child_line(st,&p->proof,machine,instance,host,device))return;
    if(mb_protected_identity_line(st,instance,host,device))return;
    const char *line=(const char *)st->owner.line;
    if(!strcmp(line,"PROTECTED_V1_HEALTH\r\n")){mb_protected_health_line(st,instance,host,device);return;}
    if(!strcmp(line,"PROTECTED_V1_NEWFS_DONE\r\n")){mb_protected_newfs_line(st,instance,host,device);return;}
    bool control=(st->owner.line_length>=16 && !memcmp(line,"PROTECTED_V1_RC:",16)) ||
        !strcmp(line,"PROTECTED_V1_NEXT\r\n") || !strcmp(line,"PROTECTED_V1_DONE\r\n");
    if(control && !mb_protected_command_line(st,instance,host,device))st->owner.failed=true;
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Same owner TU after reviewed cached adapter and protected observer.
 * This consumes the typed current-invocation grant, not a checksum as grant.
 * owner.protected is the separate protected capsule; no PUBLIC credit. */
static bool mb_protected_grant_current(void *context,
    const struct mesh_guest_enrollment_record *record,uint64_t now)
{
    struct mb_state *st=context;
    if(!st || !record)return false;
    struct mb_protected_owner *p=st->owner.protected;
    if(!p->grant_live || p->terminal || !now || now<p->admitted_ms ||
        now<p->last_decision || now>=p->authority_expires_ms)return false;
    struct mesh_guest_enrollment_record a=*record,b=p->grant;
    /* INITIAL verification adds the fingerprint; all stable identity remains
     * immutable. RECOVER already binds the exact retained fingerprint. */
    if(!st->owner.recover){memset(a.ssh_fingerprint,0,32);memset(b.ssh_fingerprint,0,32);}
    if(!mesh_guest_enrollment_equal(&a,&b))return false;
    p->last_decision=now;return true;
}
static void mb_protected_provider_invalidate(void *context)
{
    struct mb_protected_owner *p=context;
    p->terminal=true;p->grant_live=false;cached_revoke(&p->provider);
}
static void mb_protected_cached_invalidate(void *context)
{
    /* cached_callbacks receives the first member of this sole-owned capsule.
     * No manager call or filesystem operation occurs during invalidation. */
    mb_protected_provider_invalidate(context);
}
static bool mb_protected_finish_returned(struct mb_state *st,uint64_t instance,
    uint32_t host,uint32_t device)
{
    struct mb_protected_owner *p=st->owner.protected;
    if(p->proof.phase6_accepted && st->owner.command.phase!=6)return true;
    if(!p->proof.rc6_pending && !p->proof.next_pending)return true;
    /* Only invoked after manager_drive returned; consumed scans the actual
     * reposted descriptor ring and must never run from the console callback. */
    return mb_owner_protected_phase6_finish(st,&p->proof,st->m,instance,host,device);
}
static bool mb_protected_deliver_returned(struct mb_state *st,uint64_t instance,
    uint32_t host,uint32_t device,uint64_t now)
{
    struct mb_protected_owner *p=st->owner.protected;
    if(!p->proof.ready || p->configure_attempted)return !p->terminal;
    struct mesh_guest_protected_tuple tuple;
    if(!mesh_guest_service_manager_protected_tuple(st->owner.manager,instance,host,device,&tuple))
        goto refused;
    /* Reservation is already durable. high_water excludes that separately
     * reserved candidate; never reset it to zero merely on process restart. */
    p->generation_owner.high_water=tuple.provider_generation-1;
    p->configure_attempted=true;
    int64_t fresh=platform_time_monotonic_ms();
    if(fresh<=0 || (uint64_t)fresh>=p->delivery_deadline_ms ||
        !mb_protected_grant_current(st,&tuple.enrollment,(uint64_t)fresh))goto refused;
    if(!cached_configure(&p->provider,&p->generation_owner,&st->owner.credential,&tuple))goto refused;
    if(!mesh_guest_service_manager_unlock_protected(st->owner.manager,instance,
        tuple.enrollment.generation,host,device,tuple.provider_generation,now))goto refused;
    p->proof.delivered=true;p->proof.delivery_instance=instance;
    p->proof.delivery_host_epoch=host;p->proof.delivery_device_epoch=device;
    return true;
refused:
    mb_protected_provider_invalidate(p);return false;
}
static bool mb_owner_config(struct mb_state *st, struct mesh_guest_service_launch_config *config)
{
    const struct mb_owner_profile *profile = mb_owner_profile(st->owner.profile_revision);
    static const struct mb_owner_profile protected_profile={
        "a5080bb076351c5b5e058a81e5bf6ad3a0f748e97423d2214af5602a5f90097c",
        "f4201650db84c2c831e53b1914316c9cd738f8a61ee1b6f6b52bddb4688fd7f3",
        "z23.PROTECTED.geli.owner.guest.v1","z23.PROTECTED.geli.owner.profile.v1",
        "local.operator.PROTECTED.geli.keyfile.v1",
        "194bd9c2977dcab3c340472d10f8291c266bdc6fff463d0223f130886c396c4e"};
    if(st->owner.protected)profile=&protected_profile;
    if (!profile) return false;
    memset(config, 0, sizeof(*config));
    config->policy = MESH_GUEST_LAUNCH_SECRET_REQUIRED;
    config->disk_mode = MESH_GUEST_DISK_RETAINED_BACKEND;
    config->disk_bytes = UINT64_C(16) << 20;
    config->service.kernel = st->accepted.image;
    config->service.kernel_length = st->accepted.length;
    config->service.binding = mb_owner_deny_peer;
    config->service.binding_context = st;
    config->service.limits = guest_limits_default();
    config->service.machine = (struct rvmachine_config){
        .ram_bytes = st->ram_bytes, .wait_stops = true, .cleanse_on_destroy = true,
        .bootargs = "-s kern.random.initial_seeding.bypass_before_seeding=0",
        .entropy = zcl_mb_boot_host_entropy, .entropy_ctx = st, .entropy_fail_closed = true,
        .boot_seed = zcl_mb_boot_host_boot_seed, .boot_seed_ctx = st
    };
    config->unlock = (struct mesh_guest_unlock_admission){
        .policy = MESH_GUEST_UNLOCK_PUBLIC_KEYFILE_FIXTURE,
        .purpose = MESH_GUEST_UNLOCK_PUBLIC_GELI_KEYFILE, .receiver_revision = 1,
        .accepted_current = mb_owner_accepted_current,
        .public_keyfile_current = mb_owner_keyfile_current,
        .receiver_current = mb_owner_receiver_current,
        .receiver_console = mb_owner_console, .owner_context = st
    };
    memcpy(config->unlock.authorized_kernel, st->owner.authorized_kernel, 32);
    struct mesh_guest_enrollment_record *expected = &config->enrollment.expected;
    mb_owner_label_digest(profile->guest, expected->guest_id);
    memcpy(expected->kernel, st->owner.authorized_kernel, 32);
    /* Descriptive reviewed-image metadata, not separately parsed authority. */
    if (!zcl_hex_decode_lower(profile->root, expected->root, 32) ||
        !zcl_hex_decode_lower(profile->helper, expected->helper, 32)) return false;
    mb_owner_label_digest(profile->profile, expected->profile);
    mb_owner_label_digest(profile->grant, expected->owner_grant);
    struct platform_private_file_identity identity;
    if (!platform_private_file_identity(&st->owner.volume, &identity)) return false;
    expected->volume_device = identity.volume; expected->volume_file = identity.file;
    expected->volume_bytes = UINT64_C(16) << 20;
    expected->generation = 1;
    config->enrollment.volume = &st->owner.volume;
    config->enrollment.credential = &st->owner.credential;
    if (st->owner.recover) {
        struct mesh_guest_enrollment_record current;
        if (!mesh_guest_enrollment_read(&st->owner.record, &current)) return false;
        memcpy(expected->ssh_fingerprint, current.ssh_fingerprint, 32);
        expected->generation = current.generation;
        config->enrollment.mode = MESH_GUEST_ENROLLMENT_RECOVER;
        config->enrollment.record = &st->owner.record;
    } else {
        config->enrollment.mode = MESH_GUEST_ENROLLMENT_INITIAL;
        config->enrollment.initial_destination = st->owner.record_path;
    }
    st->owner.enrollment_generation = expected->generation;
    if(st->owner.protected){
        struct mb_protected_owner *p=st->owner.protected;
        int64_t now=platform_time_monotonic_ms();
        if(now<=0 || (uint64_t)now>UINT64_MAX-UINT64_C(240000))return false;
        p->admitted_ms=(uint64_t)now;p->last_decision=(uint64_t)now;
        p->delivery_deadline_ms=(uint64_t)now+GUEST_SERVICE_START_DEADLINE_MS;
        p->authority_expires_ms=(uint64_t)now+UINT64_C(240000);
        p->grant=*expected;p->grant_live=true;p->proof.image_bound=true;
        config->unlock.policy=MESH_GUEST_UNLOCK_PROTECTED_HOST;
        config->unlock.purpose=MESH_GUEST_UNLOCK_PROTECTED_GELI_KEYFILE;
        config->unlock.public_keyfile_current=NULL;
        config->unlock.receiver_current=mb_protected_receiver_current;
        config->protected_provider=cached_callbacks(&p->provider);
        config->protected_provider.credential=&st->owner.credential;
        config->protected_invalidate=mb_protected_cached_invalidate;
        config->protected_admitted_ms=p->admitted_ms;
        config->protected_delivery_deadline_ms=p->delivery_deadline_ms;
        config->protected_authority_expires_ms=p->authority_expires_ms;
        config->protected_enrollment=(struct mesh_guest_protected_enrollment_owner){
            .extension_path=p->extension_path,.fresh_stage_path=p->reserve_stage_path,
            .fresh_ready_stage_path=p->ready_stage_path,.grant_current=mb_protected_grant_current,.context=st};
    }
    return true;
}

/* Resource deadline only; completion is actual fixed receiver/child proof.
 * All machine operations below occur after a governed invocation returned. */
static bool mb_protected_progress(struct mb_state *st,uint64_t instance,uint64_t now)
{
        uint32_t host=st->m->conports[4].generation,device=st->m->con.ports[4].generation;
        if(st->owner.protected->terminal ||
            !mb_protected_finish_returned(st,instance,host,device)){
            mb_protected_provider_invalidate(st->owner.protected);return false;
        }
        if(st->owner.command_pending && !mb_owner_command(st))return false;
        if(!mb_protected_deliver_returned(st,instance,host,device,now))return false;
        if(st->owner.protected->proof.delivered)st->owner.instance=instance;
        return true;
}
static bool mb_owner_progress(struct mb_state *st, uint64_t now)
{
    uint64_t instance = mesh_guest_service_manager_instance(st->owner.manager);
    if (!instance) { st->m = NULL; return false; }
    if (!st->m) return true; /* No console observation yet. */
    if(st->owner.protected)return mb_protected_progress(st,instance,now);
    if (st->owner.instance && st->owner.instance != instance) return false;
    if (!st->m->con.ports[4].host_open) return false; /* Never rearm a closed receiver. */
    if (st->owner.command_pending && !mb_owner_command(st)) return false;
    if (!st->owner.ready || st->owner.attempted) return true;
    st->owner.attempted = true;
    st->owner.delivered = mesh_guest_service_manager_unlock_public(st->owner.manager,
        instance, st->owner.ready_epoch, now);
    /* A refused attempt may have destroyed the borrowed machine. */
    if (!mesh_guest_service_manager_instance(st->owner.manager)) st->m = NULL;
    return st->owner.delivered;
}

static bool mb_protected_proof(struct mb_state *st)
{
        if(!st->m || !st->owner.done)return false;
        uint64_t instance=mesh_guest_service_manager_instance(st->owner.manager);
        uint32_t host=st->m->conports[4].generation,device=st->m->con.ports[4].generation;
        return mb_protected_identity_current(st,instance,host,device) &&
            rvmachine_conport_consumed(st->m,4)==32 && rvmachine_conport_queued(st->m,4)==0 &&
            st->owner.public_key_seen && st->owner.fingerprint_seen &&
            mb_owner_accepted_current(st,st->owner.authorized_kernel) &&
            mb_owner_keyfile_current(st,&st->owner.credential);
}
static bool mb_owner_public_proof(struct mb_state *st)
{
    return st->m && !st->owner.failed && !st->entropy_failed &&
        st->owner.delivered && st->owner.child && st->owner.done &&
        mesh_guest_service_manager_instance(st->owner.manager) == st->owner.instance &&
        rvmachine_conport_generation(st->m, 4) == st->owner.ready_epoch &&
        st->m->con.ports[4].generation == st->owner.ready_device_epoch &&
        rvmachine_conport_consumed(st->m, 4) == 32 &&
        rvmachine_conport_queued(st->m, 4) == 0 &&
        mb_owner_accepted_current(st, st->owner.authorized_kernel) &&
        mb_owner_keyfile_current(st, &st->owner.credential);
}

static bool mb_owner_proof(struct mb_state *st)
{
    return st->owner.protected?mb_protected_proof(st):mb_owner_public_proof(st);
}
static bool mb_owner_v2_console_complete(const struct mb_state *st)
{
    return mb_owner_typed_profile(st) && st->owner.command_step == 17 &&
        !st->owner.command_pending && st->owner.command.active &&
        st->owner.command.phase == 16 && st->owner.command.rc_seen &&
        st->owner.command.done_seen && !st->owner.command.next_seen &&
        st->owner.public_key_seen && st->owner.fingerprint_seen &&
        mb_owner_identity_current(st,st->owner.command.instance,
            st->owner.command.host_epoch,st->owner.command.device_epoch);
}
static bool mb_owner_v2_before_ready(struct mb_state *st, uint64_t original_start_ms,
    uint64_t instance, uint64_t *observed_ms)
{
    /* Called outside drive: proof can load current CAS/file evidence, so sample
     * actual time AFTER those checks, not before blocking currentness reads. */
    if (!mb_owner_proof(st) || !mb_owner_v2_console_complete(st) ||
        !mesh_guest_service_manager_storage_synced(st->owner.manager, instance)) return false;
    int64_t now=platform_time_monotonic_ms();
    if (now <= 0 || (uint64_t)now < original_start_ms ||
        (uint64_t)now-original_start_ms >= GUEST_SERVICE_START_DEADLINE_MS) return false;
    *observed_ms=(uint64_t)now;
    return mesh_guest_service_manager_instance(st->owner.manager) == instance;
}
static bool mb_owner_v2_finalize(struct mb_state *st, uint64_t original_start_ms,
    uint64_t generation)
{
    uint64_t instance=st->owner.instance, now=0;
    if (!instance || !generation ||
        !mb_owner_v2_before_ready(st,original_start_ms,instance,&now)) return false;
    /* Manager checks same retained generation and existing/owned record, then
     * publish/write+file+parent flush+current-record reread. A false return or
     * late return can still follow persisted mutation. Do not claim rollback. */
    if (!st->owner.recover) st->owner.mutated=true;
    if (!mesh_guest_service_manager_identity_finish(st->owner.manager,instance,
        generation,st->owner.identity.fingerprint,true)) return false;
    if (!mb_owner_v2_before_ready(st,original_start_ms,instance,&now)) return false;
    struct guest_action action;
    if (!mesh_guest_service_manager_ready(st->owner.manager,instance,now,&action)) return false;
    /* Ready's own pre-enable TICK and pure BOOT_READY enforce original deadline.
     * This observation is reporting qualification, not retroactive rollback. */
    struct guest_service_snapshot snapshot;
    int64_t after=platform_time_monotonic_ms();
    if (after <= 0 || (uint64_t)after < original_start_ms ||
        (uint64_t)after-original_start_ms >= GUEST_SERVICE_START_DEADLINE_MS) return false;
    return mesh_guest_service_manager_instance(st->owner.manager) == instance &&
        mesh_guest_service_manager_snapshot(st->owner.manager,(uint64_t)after,&snapshot) &&
        snapshot.state == GUEST_STATE_READY && snapshot.enabled;
}

/* Exact db2440 V6 ELF FUNC intervals and executable .text/.plt sections.
 * FreeBSD locore enters these linked HIGH addresses through KERNBASE.
 * Do not classify low physical aliases or relocated user executables.
 * These are returned-slice locations, not instruction-cost measurements. */
enum { MB_PC_UNKNOWN=0, MB_PC_SHA256=1, MB_PC_AES=2, MB_PC_GELI_RUN=3,
    MB_PC_GELI_WRITE=4, MB_PC_GELI_READ=5, MB_PC_BIO=6,
    MB_PC_VIRTQUEUE=7, MB_PC_KERNEL_OTHER=8, MB_PC_BUCKETS=9 };
struct mb_pc_range { uint64_t lo, hi; unsigned bucket; };
static const struct mb_pc_range mb_pc_ranges[] = {
    {UINT64_C(0xffffffc0000cd668),UINT64_C(0xffffffc0000ce54e),MB_PC_SHA256},
    {UINT64_C(0xffffffc0000cb254),UINT64_C(0xffffffc0000cb700),MB_PC_AES},
    {UINT64_C(0xffffffc0000cb700),UINT64_C(0xffffffc0000cbbac),MB_PC_AES},
    {UINT64_C(0xffffffc0002571d4),UINT64_C(0xffffffc000257556),MB_PC_GELI_RUN},
    {UINT64_C(0xffffffc000257556),UINT64_C(0xffffffc0002577d4),MB_PC_GELI_WRITE},
    {UINT64_C(0xffffffc0002577d4),UINT64_C(0xffffffc000257b2c),MB_PC_GELI_READ},
    {UINT64_C(0xffffffc000260742),UINT64_C(0xffffffc000260a22),MB_PC_BIO},
    {UINT64_C(0xffffffc0001a4108),UINT64_C(0xffffffc0001a41ba),MB_PC_VIRTQUEUE}
};
static bool mb_pc_within(uint64_t pc, uint64_t lo, uint64_t hi)
{
    return pc >= lo && pc < hi;
}
static unsigned mb_pc_bucket(uint64_t pc)
{
    for (size_t i=0;i<sizeof mb_pc_ranges/sizeof mb_pc_ranges[0];i++)
        if (mb_pc_within(pc,mb_pc_ranges[i].lo,mb_pc_ranges[i].hi))
            return mb_pc_ranges[i].bucket;
    if (mb_pc_within(pc,UINT64_C(0xffffffc000000000),UINT64_C(0xffffffc0005841be)) ||
        mb_pc_within(pc,UINT64_C(0xffffffc0026e0480),UINT64_C(0xffffffc0026e04e0)))
        return MB_PC_KERNEL_OTHER;
    return MB_PC_UNKNOWN;
}
static unsigned mb_pc_bucket_profile(unsigned revision, uint64_t pc)
{
    static const struct mb_pc_range zbb[] = {
        {UINT64_C(0xffffffc0000cd668),UINT64_C(0xffffffc0000ce08a),MB_PC_SHA256},
        {UINT64_C(0xffffffc0000cb254),UINT64_C(0xffffffc0000cb700),MB_PC_AES},
        {UINT64_C(0xffffffc0000cb700),UINT64_C(0xffffffc0000cbbac),MB_PC_AES},
        {UINT64_C(0xffffffc000256d10),UINT64_C(0xffffffc000257092),MB_PC_GELI_RUN},
        {UINT64_C(0xffffffc000257092),UINT64_C(0xffffffc000257310),MB_PC_GELI_WRITE},
        {UINT64_C(0xffffffc000257310),UINT64_C(0xffffffc000257668),MB_PC_GELI_READ},
        {UINT64_C(0xffffffc00026027e),UINT64_C(0xffffffc00026055e),MB_PC_BIO},
        {UINT64_C(0xffffffc0001a3c44),UINT64_C(0xffffffc0001a3cf6),MB_PC_VIRTQUEUE}
    };
    static const struct mb_pc_range combined[] = {
        {UINT64_C(0xffffffc0000cd668),UINT64_C(0xffffffc0000cf874),MB_PC_SHA256},
        {UINT64_C(0xffffffc0000cb254),UINT64_C(0xffffffc0000cb700),MB_PC_AES},
        {UINT64_C(0xffffffc0000cb700),UINT64_C(0xffffffc0000cbbac),MB_PC_AES},
        {UINT64_C(0xffffffc0002584fa),UINT64_C(0xffffffc00025887c),MB_PC_GELI_RUN},
        {UINT64_C(0xffffffc00025887c),UINT64_C(0xffffffc000258afa),MB_PC_GELI_WRITE},
        {UINT64_C(0xffffffc000258afa),UINT64_C(0xffffffc000258e52),MB_PC_GELI_READ},
        {UINT64_C(0xffffffc000261a68),UINT64_C(0xffffffc000261d48),MB_PC_BIO},
        {UINT64_C(0xffffffc0001a542e),UINT64_C(0xffffffc0001a54e0),MB_PC_VIRTQUEUE}
    };
    if (revision < 4 || revision > 7) return mb_pc_bucket(pc);
    const struct mb_pc_range *ranges = revision == 4 ? mb_pc_ranges : revision == 5 ? zbb : combined;
    for (size_t i=0;i<sizeof zbb/sizeof zbb[0];i++)
        if (mb_pc_within(pc,ranges[i].lo,ranges[i].hi)) return ranges[i].bucket;
    uint64_t text_hi=revision==4?UINT64_C(0xffffffc0005841be):revision==5?UINT64_C(0xffffffc000583cee):UINT64_C(0xffffffc0005854de);
    uint64_t plt_lo=revision==4?UINT64_C(0xffffffc0026e0510):revision==5?UINT64_C(0xffffffc0026e0030):UINT64_C(0xffffffc0026e1730);
    if (mb_pc_within(pc,UINT64_C(0xffffffc000000000),text_hi) || mb_pc_within(pc,plt_lo,plt_lo+96))
        return MB_PC_KERNEL_OTHER;
    return MB_PC_UNKNOWN;
}
/* Caller must qualify PUBLIC profile2 INITIAL phase7 A1/B0 before AND after
 * actual positive-work RUN_SLICE with unchanged owned instance/dualepochs.
 * Counter overflow refuses increment WITHOUT altering execution authority. */
static bool mb_pc_count(struct mb_pc_counts *counts, unsigned bucket)
{
    if (!counts || bucket>=MB_PC_BUCKETS || counts->total==UINT32_MAX ||
        counts->hit[bucket]==UINT32_MAX) return false;
    counts->hit[bucket]++; counts->total++;
    return true;
}
static unsigned mb_pc_top(const struct mb_pc_counts *counts)
{
    unsigned top=0; uint32_t highest=0;
    for (unsigned i=1;i<MB_PC_BUCKETS;i++)
        if (counts->hit[i]>highest) { highest=counts->hit[i]; top=i; }
    return top; /* 0 means no matched kernel sample; UNKNOWN never dominates. */
}
static bool mb_owner_pc_scope(struct mb_state *st)
{
    bool profile = st->owner.profile_revision == 2 ||
        (mb_owner_prepared_profile(st) && mb_owner_pc_formatting(st));
    return st->owner.enabled && profile &&
        !st->owner.recover && !st->owner.identity_ready &&
        !st->owner.public_key_seen && !st->owner.fingerprint_seen &&
        st->owner.command_step == 8 && st->owner.command.active &&
        st->owner.command.phase == 7 && !st->owner.command.rc_seen &&
        st->accepted.image && st->accepted.length == mb_owner_image_bytes(st) &&
        zcl_mb_owner_image_grant(st, st->accepted.root, NULL);
}
struct mb_pc_context {
    const struct rvmachine *machine;
    uint64_t instance, retired, fw_calls, device_work;
    uint32_t host_epoch, device_epoch;
    bool valid;
};
static struct mb_pc_context mb_owner_phase7_context(struct mb_state *st, bool need_dd)
{
    struct mb_pc_context c = {0};
    if (!mb_owner_pc_scope(st) || (need_dd && !mb_owner_pc_formatting(st)) ||
        st->owner.phase7_newfs_done || !st->owner.manager) return c;
    /* A stopped instance may leave the borrowed pointer dangling. */
    c.instance = mesh_guest_service_manager_instance(st->owner.manager);
    if (!c.instance || c.instance != st->owner.instance || !st->m) return c;
    if (st->m->con.busy || st->m->conport_count <= 4 ||
        st->m->conports[4].seen_generation != st->m->con.ports[4].generation) return c;
    c.host_epoch = st->m->conports[4].generation;
    c.device_epoch = st->m->con.ports[4].generation;
    if (!mb_owner_pc_phase7_current(st, c.instance, c.host_epoch, c.device_epoch) ||
        !mb_owner_identity_current(st, c.instance, c.host_epoch, c.device_epoch)) return c;
    c.machine = st->m;
    c.retired = st->owner.last_retired;
    c.fw_calls = st->owner.last_fw_calls;
    c.device_work = st->owner.last_device_work;
    c.valid = true;
    return c;
}
static struct mb_pc_context mb_owner_pc_context(struct mb_state *st)
{
    return mb_owner_phase7_context(st, true);
}
static struct mb_pc_context mb_owner_p7_context(struct mb_state *st)
{
    if (st->owner.profile_revision != 2) return (struct mb_pc_context){0};
    struct mb_pc_context c = mb_owner_phase7_context(st, false);
    c.valid = c.valid && st->owner.last_result_valid;
    return c;
}
static bool mb_pc_same(const struct mb_pc_context *a, const struct mb_pc_context *b)
{
    return a->valid && b->valid && a->machine == b->machine &&
        a->instance == b->instance && a->host_epoch == b->host_epoch &&
        a->device_epoch == b->device_epoch;
}
static bool mb_pc_positive(const struct mb_pc_context *before, const struct rvmachine_result *r)
{
    return r->retired >= before->retired && r->fw_calls >= before->fw_calls &&
        r->device_work >= before->device_work &&
        (r->retired > before->retired || r->fw_calls > before->fw_calls ||
         r->device_work > before->device_work);
}
static bool mb_p7_sum(uint64_t retired, uint64_t fw, uint64_t device, uint64_t *out)
{
    if (fw > UINT64_MAX - retired) return false;
    uint64_t sum = retired + fw;
    if (device > UINT64_MAX - sum) return false;
    *out = sum + device;
    return true;
}
static void mb_v3_dispatch_observe(struct mb_v3_dispatch *d, size_t previous,
    size_t current, const struct mb_pc_context *c)
{
    if (d->seen || previous != 7 || current != 8) return;
    d->seen = true;
    uint64_t work = 0;
    if (!c->valid || !c->machine || !c->instance || !c->host_epoch || !c->device_epoch ||
        !mb_p7_sum(c->retired, c->fw_calls, c->device_work, &work)) return;
    d->work = work; d->machine = c->machine; d->instance = c->instance;
    d->host_epoch = c->host_epoch; d->device_epoch = c->device_epoch; d->valid = true;
}
static bool mb_v3_dispatch_same(const struct mb_v3_dispatch *d, const struct mb_pc_context *c)
{
    return d->seen && d->valid && c->valid && d->machine == c->machine &&
        d->instance == c->instance && d->host_epoch == c->host_epoch && d->device_epoch == c->device_epoch;
}
static void mb_owner_v3_dispatch_summary(struct mb_state *st, char out[24])
{
    out[0] = 0;
    if (!mb_owner_prepared_profile(st) || st->owner.recover || st->owner.command_step != 8) return;
    const struct mb_v3_dispatch *d = &st->owner.v3_dispatch;
    if (!d->seen) snprintf(out, 24, " d=unknown");
    else if (!d->valid || d->work > UINT32_MAX) snprintf(out, 24, " d=unavailable");
    else snprintf(out, 24, " d=%u", (unsigned)(uint32_t)d->work);
}
static void mb_p7_dispatch_observe(struct mb_p7_bracket *b,
    size_t previous_step, size_t current_step, const struct mb_pc_context *c)
{
    if (b->dispatch_seen || previous_step != 7 || current_step != 8) return;
    b->dispatch_seen = true;
    uint64_t total = 0;
    if (!c->valid || !c->machine || !c->instance || !c->host_epoch || !c->device_epoch ||
        !mb_p7_sum(c->retired, c->fw_calls, c->device_work, &total)) return;
    b->dispatch = total;
    b->dispatch_machine = c->machine;
    b->dispatch_instance = c->instance;
    b->dispatch_host_epoch = c->host_epoch;
    b->dispatch_device_epoch = c->device_epoch;
    b->dispatch_valid = true;
}
static bool mb_p7_dispatch_same(const struct mb_p7_bracket *b, const struct mb_pc_context *c)
{
    return b->dispatch_seen && b->dispatch_valid && c->valid &&
        b->dispatch_machine == c->machine && b->dispatch_instance == c->instance &&
        b->dispatch_host_epoch == c->host_epoch && b->dispatch_device_epoch == c->device_epoch;
}
/* Bounds the returned slice containing the first P7A, not its exact cost. */
static void mb_p7_observe(struct mb_p7_bracket *b,
    const struct mb_pc_context *before, const struct mb_pc_context *after,
    bool dd_before, bool dd_after, enum rvmachine_status status,
    const struct guest_gov_decision *decision, const struct rvmachine_result *r)
{
    if (b->seen || dd_before || !dd_after) return;
    b->seen = true; /* Refused crossings never rearm. */
    if (!mb_p7_dispatch_same(b, before) || !mb_p7_dispatch_same(b, after)) return;
    if (decision->kind != GUEST_GOV_RUN_SLICE ||
        (status != RVMACHINE_OK && status != RVMACHINE_ERR_WAITING) ||
        !mb_pc_same(before, after) || !mb_pc_positive(before, r)) return;
    uint64_t lower = 0, upper = 0;
    if (!mb_p7_sum(before->retired, before->fw_calls, before->device_work, &lower) ||
        !mb_p7_sum(r->retired, r->fw_calls, r->device_work, &upper) ||
        upper <= lower || b->dispatch > lower) return;
    b->lower = lower;
    b->upper = upper;
    b->valid = true;
}
static bool mb_p7_reportable(const struct mb_p7_bracket *b)
{
    return b->dispatch_seen && b->dispatch_valid && b->valid &&
        b->dispatch <= b->lower && b->lower < b->upper &&
        b->dispatch <= UINT32_MAX && b->lower <= UINT32_MAX && b->upper <= UINT32_MAX;
}
static void mb_owner_p7_summary(struct mb_state *st, char out[48])
{
    out[0] = 0;
    if (st->owner.profile_revision != 2 || !mb_owner_pc_scope(st)) return;
    const struct mb_p7_bracket *b = &st->owner.p7_bracket;
    if (!b->seen) snprintf(out, 48, " a=unknown");
    else if (!mb_p7_reportable(b)) snprintf(out, 48, " a=unavailable");
    else snprintf(out, 48, " a=%u:%u:%u", (unsigned)(uint32_t)b->dispatch,
        (unsigned)(uint32_t)b->lower, (unsigned)(uint32_t)b->upper);
}
/* Diagnostic origin: epochs may be zero before the receiver is opened. */
static bool mb_owner_work_trace_scope(const struct mb_state *st)
{
    return !st->owner.recover && (mb_owner_prepared_profile(st)||st->owner.protected);
}
static bool mb_protected_trace_bind(struct mb_state *st,const struct mb_pc_context *c)
{
    struct mb_protected_owner *p=st->owner.protected;
    if(!p)return true;
    if(!mb_protected_identity_current(st,c->instance,c->host_epoch,c->device_epoch)){
        if(p->trace_bound)p->trace_invalid=true;
        return false;
    }
    if(!p->trace_bound){
        p->trace_bound=true;
        memcpy(p->trace_kernel,st->owner.authorized_kernel,32);
        memcpy(p->trace_root,st->accepted.root,32);
        p->trace_tuple=(struct mb_v3_dispatch){.machine=c->machine,.instance=c->instance,
            .host_epoch=c->host_epoch,.device_epoch=c->device_epoch,.seen=true,.valid=true};
    }
    if(!mb_v3_dispatch_same(&p->trace_tuple,c)||
        memcmp(p->trace_kernel,st->owner.authorized_kernel,32)||
        memcmp(p->trace_root,st->accepted.root,32))p->trace_invalid=true;
    return !p->trace_invalid;
}
static struct mb_pc_context mb_owner_transition_context(struct mb_state *st)
{
    struct mb_pc_context c={0};
    if (!mb_owner_work_trace_scope(st) || !st->owner.manager) return c;
    uint64_t instance=mesh_guest_service_manager_instance(st->owner.manager);
    if (!instance) return c; /* Teardown: retain explicitly historical integers. */
    if (!st->m || st->owner.line_instance!=instance || st->m->conport_count!=5){
        if(st->owner.protected && st->owner.protected->trace_bound)
            st->owner.protected->trace_invalid=true;
        return c;
    }
    c.machine=st->m; c.instance=instance;
    c.host_epoch=st->m->conports[4].generation;
    c.device_epoch=st->m->con.ports[4].generation;
    c.retired=st->owner.last_retired; c.fw_calls=st->owner.last_fw_calls;
    c.device_work=st->owner.last_device_work; c.valid=true;
    c.valid=mb_protected_trace_bind(st,&c);
    return c;
}
static void mb_trace_actual_observe(struct mb_v3_dispatch *origin,
    const struct mb_pc_context *before,const struct mb_pc_context *after,
    const struct guest_gov_decision *decision,enum rvmachine_status status)
{
    if (decision->kind!=GUEST_GOV_RUN_SLICE ||
        (!after->retired && !after->fw_calls && !after->device_work)) return;
    origin->seen=true; origin->valid=false;
    uint64_t work=0;
    if ((status!=RVMACHINE_OK && status!=RVMACHINE_ERR_WAITING) ||
        !mb_pc_same(before,after) || after->retired<before->retired ||
        after->fw_calls<before->fw_calls || after->device_work<before->device_work ||
        !mb_p7_sum(after->retired,after->fw_calls,after->device_work,&work)) return;
    *origin=(struct mb_v3_dispatch){.work=work,.machine=after->machine,
        .instance=after->instance,.host_epoch=after->host_epoch,
        .device_epoch=after->device_epoch,.seen=true,.valid=true};
}
static void mb_trace_actual_result_observe(struct mb_v3_dispatch *origin,
    const struct mb_pc_context *before,const struct mb_pc_context *after,
    const struct guest_gov_decision *decision,enum rvmachine_status status,
    const struct rvmachine_result *result)
{
    if (!result->retired && !result->fw_calls && !result->device_work) return;
    mb_trace_actual_observe(origin,before,after,decision,status);
}
static void mb_trace_dispatch_observe(struct mb_v3_dispatch trace[17],uint32_t *attempted,
    size_t previous,size_t current,const struct mb_v3_dispatch *origin,
    const struct mb_pc_context *context)
{
    if (previous>=17 || current!=previous+1 || (*attempted&(1u<<previous))) return;
    *attempted|=(uint32_t)(1u<<previous);
    struct mb_v3_dispatch *entry=&trace[previous];
    if (!origin->seen) return;
    entry->seen=true;
    uint64_t work=0;
    if (!mb_v3_dispatch_same(origin,context) ||
        !mb_p7_sum(context->retired,context->fw_calls,context->device_work,&work) || work!=origin->work) return;
    for (size_t i=0;i<previous;i++) {
        if (trace[i].valid && (trace[i].machine!=origin->machine ||
            trace[i].instance!=origin->instance || trace[i].work>work)) return;
    }
    *entry=*origin;
}
static void mb_trace_value(const struct mb_v3_dispatch *entry,char out[12])
{
    if (!entry->seen) snprintf(out,12,"unknown");
    else if (!entry->valid || entry->work>UINT32_MAX) snprintf(out,12,"unavailable");
    else snprintf(out,12,"%u",(unsigned)(uint32_t)entry->work);
}
static void mb_owner_late_trace_message(const struct mb_state *st,char out[192])
{
    size_t phase=st->owner.command_step-1;
    char latest[12],format[12];
    mb_trace_value(&st->owner.phase_dispatch[phase],latest);
    mb_trace_value(&st->owner.phase_dispatch[7],format);
    size_t used=strlen(out);
    snprintf(out+used,192-used,"; phase=%zu dispatch=%s format_dispatch=%s",phase,latest,format);
}
static void mb_owner_trace_message(const struct mb_state *st,char out[192])
{
    const char *message="fixed PUBLIC policy, admission, delivery, or actual child proof refused";
    snprintf(out,192,"%s",message);
    if (!mb_owner_prepared_profile(st) || st->owner.recover ||
        st->owner.command_step<8 || st->owner.command_step>17) return;
    if (st->owner.command_step>8) {
        mb_owner_late_trace_message(st,out);
        return;
    }

    size_t used=strlen(out);
    int n=snprintf(out+used,192-used,"; dispatch[0..7]=");
    if (n<0 || (size_t)n>=192-used) return;
    used+=(size_t)n;
    for (unsigned i=0;i<8;i++) {
        const struct mb_v3_dispatch *entry=&st->owner.phase_dispatch[i];
        char value[12];
        if (!entry->seen) snprintf(value,sizeof value,"unknown");
        else if (!entry->valid || entry->work>UINT32_MAX) snprintf(value,sizeof value,"unavailable");
        else snprintf(value,sizeof value,"%u",(unsigned)(uint32_t)entry->work);
        n=snprintf(out+used,192-used,"%s%s",i?":":"",value);
        if (n<0 || (size_t)n>=192-used) return;
        used+=(size_t)n;
    }
}
static void mb_owner_pc_privilege_observe(struct mb_state *st,
    const struct mb_pc_context *before,const struct mb_pc_context *after)
{
    if(st->owner.profile_revision!=7)return;
    if(!mb_pc_positive(before,&st->res))return;
    struct mb_pc_privileges *p=&st->owner.pc_privileges;
    if(!mb_pc_same(before,after)||!st->m||after->machine!=st->m||
        st->res.pc!=st->m->hart.pc){p->unavailable=true;return;}
    unsigned mode=st->m->hart.priv;
    unsigned bucket=mode==RVEMU_PRIV_U?0:mode==RVEMU_PRIV_S?1:mode==RVEMU_PRIV_M?2:3;
    if(p->hit[bucket]==UINT16_MAX){p->unavailable=true;return;}
    p->hit[bucket]++;
    struct mb_p7_privilege_history *h=&st->owner.p7_privilege_history;
    uint64_t work=0;
    if(!mb_p7_sum(st->res.retired,st->res.fw_calls,st->res.device_work,&work)){
        h->unavailable=true;return;
    }
    h->sample=(struct mb_v3_dispatch){.machine=after->machine,.instance=after->instance,
        .host_epoch=after->host_epoch,.device_epoch=after->device_epoch,
        .work=work,.seen=true,.valid=true};
    h->dispatch=st->owner.v3_dispatch;
    memcpy(h->kernel,st->owner.authorized_kernel,32);memcpy(h->root,st->accepted.root,32);
}
static bool mb_p7_history_tuple(const struct mb_v3_dispatch *a,const struct mb_v3_dispatch *b)
{
    return a->seen && a->valid && b->seen && b->valid && a->machine==b->machine &&
        a->instance==b->instance && a->host_epoch==b->host_epoch && a->device_epoch==b->device_epoch;
}
static void mb_owner_p7_privilege_validate(struct mb_state *st);
static void mb_owner_p7_privilege_freeze(struct mb_state *st,bool completed)
{
    if(st->owner.profile_revision!=7 || st->owner.recover || !completed)return;
    struct mb_p7_privilege_history *h=&st->owner.p7_privilege_history;
    if(h->seen){h->unavailable=true;return;}
    h->seen=true;h->completed=st->owner.phase_dispatch[8];
    h->counts=st->owner.pc_privileges;h->total=st->owner.pc_counts.total;
    if(!mb_p7_history_tuple(&h->sample,&h->completed) ||
        !mb_p7_history_tuple(&h->sample,&h->dispatch) ||
        h->sample.work<h->dispatch.work || h->completed.work<h->sample.work ||
        h->counts.unavailable || st->owner.pc_unqualified) h->unavailable=true;
    /* This is the live completion boundary, not a later teardown query. */
    if(!st->owner.manager || !mesh_guest_service_manager_instance(st->owner.manager))
        h->unavailable=true;
    mb_owner_p7_privilege_validate(st);
}
/* Refresh only while the producing instance is live. A stopped manager does
 * not revoke an already qualified historical observation. */
static void mb_owner_p7_privilege_validate(struct mb_state *st)
{
    struct mb_p7_privilege_history *h=&st->owner.p7_privilege_history;
    if(!h->seen)return;
    if(!st->owner.manager || !mesh_guest_service_manager_instance(st->owner.manager))return;
    struct mb_pc_context c=mb_owner_transition_context(st);
    struct mb_v3_dispatch current={.machine=c.machine,.instance=c.instance,
        .host_epoch=c.host_epoch,.device_epoch=c.device_epoch,.seen=true,.valid=c.valid};
    bool image=memcmp(h->kernel,st->owner.authorized_kernel,32)==0 &&
        memcmp(h->root,st->accepted.root,32)==0 && zcl_mb_owner_image_grant(st,st->accepted.root,NULL);
    uint32_t total=0;for(unsigned i=0;i<4;i++)total+=h->counts.hit[i];
    if(!h->seen || !image || !mb_p7_history_tuple(&h->completed,&current) ||
        !mb_p7_history_tuple(&h->completed,&st->owner.phase_dispatch[8]) ||
        h->completed.work!=st->owner.phase_dispatch[8].work || total!=h->total)
        h->unavailable=true;
}
static void mb_owner_p7_privilege_history(struct mb_state *st,char out[32])
{
    out[0]=0;
    if(st->owner.profile_revision!=7 || st->owner.recover || st->owner.command_step<9)return;
    struct mb_p7_privilege_history *h=&st->owner.p7_privilege_history;
    mb_owner_p7_privilege_validate(st);
    uint32_t total=0;for(unsigned i=0;i<4;i++)total+=h->counts.hit[i];
    if(!h->seen || memcmp(h->kernel,st->owner.authorized_kernel,32)!=0 ||
        memcmp(h->root,st->accepted.root,32)!=0 ||
        !mb_p7_history_tuple(&h->completed,&st->owner.phase_dispatch[8]) ||
        h->completed.work!=st->owner.phase_dispatch[8].work || total!=h->total)
        h->unavailable=true;
    if(h->unavailable){snprintf(out,32," p7priv=unavailable");return;}
    snprintf(out,32," p7priv=%04x/%04x/%04x/%04x",(unsigned)h->counts.hit[0],
        (unsigned)h->counts.hit[1],(unsigned)h->counts.hit[2],(unsigned)h->counts.hit[3]);
}
static void mb_owner_pc_privilege_summary(struct mb_state *st,char out[24])
{
    out[0]=0;
    if(st->owner.profile_revision!=7||!mb_owner_pc_scope(st))return;
    const struct mb_pc_privileges *p=&st->owner.pc_privileges;
    uint32_t total=0;
    for(unsigned i=0;i<4;i++)total+=p->hit[i];
    if(p->unavailable||st->owner.pc_unqualified||total!=st->owner.pc_counts.total){
        snprintf(out,24," p=unavailable");return;
    }
    snprintf(out,24," p=%04x/%04x/%04x/%04x",(unsigned)p->hit[0],
        (unsigned)p->hit[1],(unsigned)p->hit[2],(unsigned)p->hit[3]);
}
static void mb_owner_pc_observe(struct mb_state *st, const struct mb_pc_context *before,
    enum rvmachine_status status, const struct guest_gov_decision *decision)
{
    if (!before->valid || decision->kind != GUEST_GOV_RUN_SLICE ||
        (status != RVMACHINE_OK && status != RVMACHINE_ERR_WAITING) ||
        !mb_pc_positive(before, &st->res)) return;
    struct mb_pc_context after = mb_owner_pc_context(st);
    if (!mb_pc_same(before, &after)) return;
    if (mb_owner_prepared_profile(st) &&
        (!mb_v3_dispatch_same(&st->owner.v3_dispatch, before) ||
         !mb_v3_dispatch_same(&st->owner.v3_dispatch, &after))) {
        st->owner.pc_unqualified = true;
        return;
    }
    if (!mb_pc_count(&st->owner.pc_counts, mb_pc_bucket_profile(st->owner.profile_revision, st->res.pc)))
        st->owner.pc_unqualified = true;
    else mb_owner_pc_privilege_observe(st,before,&after);
}
static void mb_owner_pc_summary(struct mb_state *st, char out[48])
{
    out[0] = 0;
    if (!mb_owner_pc_scope(st)) return;
    uint64_t sum = 0;
    for (unsigned i = 0; i < MB_PC_BUCKETS; i++) sum += st->owner.pc_counts.hit[i];
    if (st->owner.pc_unqualified || sum != st->owner.pc_counts.total) {
        snprintf(out, 48, " k=unavailable");
        return;
    }
    unsigned top = mb_pc_top(&st->owner.pc_counts);
    snprintf(out, 48, " k=%u:%u/%u u=%u", top,
        top ? (unsigned)st->owner.pc_counts.hit[top] : 0u,
        (unsigned)st->owner.pc_counts.total, (unsigned)st->owner.pc_counts.hit[0]);
}
static void mb_owner_geometry_summary(struct mb_state *st, char out[24])
{
    out[0] = 0;
    if (!mb_owner_pc_scope(st)) return;
    if (st->owner.geometry_unqualified ||
        (st->owner.geometry_seen && !mb_geometry_bounded(&st->owner.geometry)))
        snprintf(out,24," g=unavailable");
    else if (!st->owner.geometry_seen) snprintf(out,24," g=unknown");
    else snprintf(out,24," g=%u:%u:%u",(unsigned)(uint16_t)st->owner.geometry.groups,
        (unsigned)(uint16_t)st->owner.geometry.blocks,(unsigned)(uint16_t)st->owner.geometry.inodes);
}
static bool mb_owner_work(const struct rvmachine_result *result, uint64_t cap)
{
    /* fill_result reports cumulative work since load, not this slice's delta.
     * This owner retains one machine and refuses replacement; never sum totals. */
    if (result->retired > cap) return false;
    cap -= result->retired;
    if (result->fw_calls > cap) return false;
    return result->device_work <= cap - result->fw_calls;
}

static void mb_owner_result_remember(struct mb_state *st,
    const struct guest_gov_decision *decision, enum rvmachine_status status)
{
    if (!st->res.retired && !st->res.fw_calls && !st->res.device_work) return;
    st->owner.last_retired = st->res.retired;
    st->owner.last_fw_calls = st->res.fw_calls;
    st->owner.last_device_work = st->res.device_work;
    st->owner.last_result_valid = decision->kind == GUEST_GOV_RUN_SLICE &&
        (status == RVMACHINE_OK || status == RVMACHINE_ERR_WAITING);
}
static bool mb_owner_format_command_completed(const struct mb_state *st)
{
    return st->owner.command_step==8 && st->owner.command.phase==7 &&
        st->owner.command.rc_seen && st->owner.command.next_seen && st->owner.v3_newfs_done;
}
static bool mb_protected_format_command_completed(const struct mb_state *st)
{
    return st->owner.protected && st->owner.command_step==8 &&
        st->owner.command.phase==7 && st->owner.command.rc_seen &&
        st->owner.command.next_seen && st->owner.protected->newfs_done;
}
static void mb_protected_format_observe(struct mb_state *st,bool completed)
{
    if(completed && st->owner.command_step==9 && st->owner.phase_dispatch[8].valid)
        st->owner.protected->format_completed=true;
}
static bool mb_owner_dispatch_progress(struct mb_state *st, uint64_t now)
{
    size_t previous_step = st->owner.command_step;
    bool completed=mb_owner_format_command_completed(st);
    bool protected_completed=mb_protected_format_command_completed(st);
    if (!mb_owner_progress(st, now)) return false;
    if (mb_owner_work_trace_scope(st)) {
        struct mb_pc_context context=mb_owner_transition_context(st);
        if (previous_step && !mb_command_current(&st->owner.command,
            (unsigned)previous_step,context.instance,context.host_epoch,context.device_epoch)) context.valid=false;
        mb_trace_dispatch_observe(st->owner.phase_dispatch,&st->owner.phase_dispatch_attempted,
            previous_step,st->owner.command_step,&st->owner.transition_actual,&context);
        mb_protected_format_observe(st,protected_completed);
    }
    mb_owner_p7_privilege_freeze(st,completed && st->owner.command_step==9);
    struct mb_pc_context current = mb_owner_p7_context(st);
    if (st->owner.profile_revision == 2)
        mb_p7_dispatch_observe(&st->owner.p7_bracket, previous_step,
            st->owner.command_step, &current);
    if (mb_owner_prepared_profile(st) && !st->owner.recover) {
        struct mb_pc_context v3 = mb_owner_phase7_context(st, false);
        v3.valid = v3.valid && st->owner.last_result_valid;
        mb_v3_dispatch_observe(&st->owner.v3_dispatch, previous_step, st->owner.command_step, &v3);
        if (st->owner.v3_dispatch.seen && !st->owner.v3_dispatch.valid)
            st->owner.pc_unqualified = true;
    }
    return true;
}
static bool mb_owner_round(struct mb_state *st, uint64_t end)
{
    int64_t now = platform_time_monotonic_ms();
    if (now <= 0 || (uint64_t)now >= end || st->owner.failed || st->entropy_failed) return false;
    if (!mb_owner_dispatch_progress(st, (uint64_t)now)) return false;
    struct mb_pc_context before = mb_owner_pc_context(st);
    struct mb_pc_context transition_before=mb_owner_transition_context(st);
    struct mb_pc_context p7_before = mb_owner_p7_context(st);
    mb_owner_p7_privilege_validate(st);
    bool dd_before = st->owner.phase7_dd_done;
    struct guest_gov_decision decision;
    enum rvmachine_status status = mesh_guest_service_manager_drive(st->owner.manager,
        (uint64_t)now, platform_time_wall_unix(), &decision, &st->res);
    /* A no-run drive clears res; retain the last actual cumulative counters
     * for diagnostics instead of reporting that a stopped guest did no work. */
    mb_owner_result_remember(st, &decision, status);
    struct mb_pc_context transition_after=mb_owner_transition_context(st);
    mb_trace_actual_result_observe(&st->owner.transition_actual,&transition_before,
        &transition_after,&decision,status,&st->res);
    int64_t observed = platform_time_monotonic_ms();
    if (!mesh_guest_service_manager_instance(st->owner.manager)) st->m = NULL;
    mb_owner_p7_privilege_validate(st);
    struct mb_pc_context p7_after = mb_owner_p7_context(st);
    mb_p7_observe(&st->owner.p7_bracket, &p7_before, &p7_after,
        dd_before, st->owner.phase7_dd_done, status, &decision, &st->res);
    mb_owner_pc_observe(st, &before, status, &decision);
    if (observed <= 0 || (uint64_t)observed >= end ||
        (status != RVMACHINE_OK && status != RVMACHINE_ERR_WAITING) ||
        !mb_owner_work(&st->res, st->max_work)) return false;
    return true;
}

static bool mb_owner_loop(struct mb_state *st, uint64_t end)
{
    while (!st->owner.done) {
        if (!mb_owner_round(st, end)) return false;
        if (!st->owner.done) platform_sleep_ms(1); /* Preserve governor admission, no busy spin. */
    }
    if (!mb_owner_proof(st)) return false;
    if (mb_owner_typed_profile(st)) {
        if (!mb_owner_v2_finalize(st, st->owner.started_ms, st->owner.enrollment_generation)) return false;
        st->owner.identity_ready = true;
    }
    int64_t observed = platform_time_monotonic_ms();
    return observed > 0 && (uint64_t)observed < end;
}

/* False retains the complete capsule, including every callback and lock.
 * No borrowed machine is destroyed independently of its manager. */
static bool mb_owner_join(struct mb_state *st, struct zcl_command_reply *reply)
{
    mb_owner_p7_privilege_validate(st);
    int64_t now = platform_time_monotonic_ms();
    if (st->owner.manager && (now <= 0 ||
        !mesh_guest_service_manager_destroy(st->owner.manager, (uint64_t)now))) {
        st->owner.retained = true;
        mb_public_owner_retained = st;
        (void)zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "PUBLIC_OWNER_CLEANUP_UNOBSERVED", "stop",
            "the owned manager did not join; its callback contexts and locks remain retained", MB_PATH);
        reply->error.mutated = st->owner.mutated;
        return false;
    }
    st->owner.manager = NULL;
    st->m = NULL;
    return true;
}

/* Fixed PUBLIC state only: no console bytes, credentials or private paths.
 * Capture lifecycle before destroy, which would replace the failure state. */
static void mb_protected_work_summary(struct mb_state *st,char out[96])
{
    struct mb_protected_owner *p=st->owner.protected;
    char dispatch[12],complete[12];
    mb_trace_value(&st->owner.phase_dispatch[7],dispatch);
    if(p->format_completed)mb_trace_value(&st->owner.phase_dispatch[8],complete);
    else snprintf(complete,sizeof complete,"unknown");
    if(p->trace_invalid || (p->trace_bound &&
        (memcmp(p->trace_kernel,st->owner.authorized_kernel,32) ||
         memcmp(p->trace_root,st->accepted.root,32)))){
        p->trace_invalid=true;
        snprintf(dispatch,sizeof dispatch,"unavailable");
        snprintf(complete,sizeof complete,"unavailable");
    }
    /* Completed is a returned/enqueue upper boundary after accepted RC7/NEXT,
     * not exact formatter retirement or an identity/readiness assertion. */
    snprintf(out,96," phase=%zu format_dispatch=%s format_return=%s",
        st->owner.command_step?st->owner.command_step-1:0,dispatch,complete);
}
static bool mb_owner_refusal(struct mb_state *st, struct zcl_command_reply *reply,
    const struct guest_service_snapshot *snapshot)
{
    if(st->owner.protected){
        (void)zcl_mb_boot_fail(reply,ZCL_COMMAND_EXIT_FAILED,"PROTECTED_OWNER_REFUSED","owner",
            "distinct protected policy, current grant, delivery, or actual child/identity proof refused",MB_PATH);
        reply->error.mutated=st->owner.mutated;
        if(snapshot)snprintf(reply->error.current_state,sizeof(reply->error.current_state),"%s/%s",
            guest_state_name(snapshot->state),guest_reason_name(snapshot->last_failure));
        snprintf(reply->error.evidence,sizeof(reply->error.evidence),
            "PROTECTED owner step=%zu grant=%d delivered=%d child=%d done=%d work=%llu/%llu/%llu",
            st->owner.command_step,st->owner.protected->grant_live,st->owner.protected->proof.delivered,
            st->owner.protected->proof.child,st->owner.done,(unsigned long long)st->owner.last_retired,
            (unsigned long long)st->owner.last_fw_calls,(unsigned long long)st->owner.last_device_work);
        char work_summary[96];mb_protected_work_summary(st,work_summary);
        size_t used=strlen(reply->error.evidence),extra=strlen(work_summary);
        if(extra<sizeof(reply->error.evidence)-used)
            memcpy(reply->error.evidence+used,work_summary,extra+1);
        return false;
    }
    char message[192];
    mb_owner_trace_message(st,message);
    (void)zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "PUBLIC_OWNER_REFUSED", "fixture",
        message, MB_PATH);
    reply->error.mutated = st->owner.mutated;
    if (snapshot)
        snprintf(reply->error.current_state, sizeof(reply->error.current_state), "%s/%s",
            guest_state_name(snapshot->state), guest_reason_name(snapshot->last_failure));
    char pc_summary[48];
    char geometry_summary[24];
    char p7_summary[48];
    char v3_dispatch_summary[24];
    char privilege_summary[32];
    mb_owner_pc_summary(st, pc_summary);
    mb_owner_geometry_summary(st, geometry_summary);
    mb_owner_p7_summary(st, p7_summary);
    mb_owner_v3_dispatch_summary(st, v3_dispatch_summary);
    mb_owner_pc_privilege_summary(st,privilege_summary);
    if(!privilege_summary[0])mb_owner_p7_privilege_history(st,privilege_summary);
    snprintf(reply->error.evidence, sizeof(reply->error.evidence),
        "PUBLIC owner step=%zu health=%d ready=%d attempted=%d delivered=%d child=%d done=%d "
        "work=%llu/%llu/%llu p7=%u:%u%s%s%s%s%s",
        st->owner.command_step, st->owner.health, st->owner.ready, st->owner.attempted,
        st->owner.delivered, st->owner.child, st->owner.done,
        (unsigned long long)st->owner.last_retired, (unsigned long long)st->owner.last_fw_calls,
        (unsigned long long)st->owner.last_device_work,
        (unsigned)st->owner.phase7_dd_done, (unsigned)st->owner.phase7_newfs_done,
        pc_summary, geometry_summary, p7_summary, mb_owner_v3_newfs_summary(st), v3_dispatch_summary);
    size_t used=strlen(reply->error.evidence),extra=strlen(privilege_summary);
    /* Never truncate established fields to add optional attribution. An
     * absent p field is unavailable, not a zero/user/kernel observation. */
    if(extra<sizeof(reply->error.evidence)-used)
        memcpy(reply->error.evidence+used,privilege_summary,extra+1);
    return false;
}

static bool mb_owner_start(struct mb_state *st, uint64_t now)
{
    struct guest_action action;
    st->owner.started_ms = now;
    return mesh_guest_service_manager_event(st->owner.manager,
        &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, now, &action) &&
        mb_owner_accepted_current(st, st->owner.authorized_kernel) &&
        mesh_guest_service_manager_event(st->owner.manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, now, &action) &&
        mesh_guest_service_manager_instance(st->owner.manager) != 0 &&
        mb_owner_loop(st, now + UINT64_C(240000));
}

static bool mb_owner_identity_reply(const struct mb_state *st, struct zcl_command_reply *reply)
{
    if (!st->owner.identity_ready) return true;
    char fingerprint[65], wire[69];
    zcl_hex_encode(st->owner.identity.fingerprint, 32, fingerprint);
    if (zbase64_encode(st->owner.identity.wire, sizeof(st->owner.identity.wire), wire, sizeof wire) &&
        json_push_kv_str(&reply->data, "ssh_fingerprint_sha256", fingerprint) &&
        json_push_kv_str(&reply->data, "ssh_public_key_wire_base64", wire)) return true;
    (void)zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "PUBLIC_IDENTITY_ENCODING", "result",
        "verified PUBLIC identity could not be encoded or added to the result", MB_PATH);
    reply->error.mutated = st->owner.mutated;
    return false;
}

static bool mb_owner_prepare(struct mb_state *st, struct zcl_command_reply *reply)
{
    struct mesh_guest_service_launch_config config;
    return zcl_mb_boot_accepted_read(st, reply) &&
        mb_owner_accepted_current(st, st->owner.authorized_kernel) &&
        mb_owner_files(st) && mb_owner_config(st, &config) &&
        mesh_guest_service_manager_create(&st->owner.manager, &config);
}

static bool mb_owner_start_authority_current(const struct mb_state *st,uint64_t now)
{
    const struct mb_protected_owner *p=st->owner.protected;
    if(!p)return true;
    return p->grant_live&&!p->terminal&&now>=p->admitted_ms&&now>=p->last_decision&&
        now<p->delivery_deadline_ms&&now<p->authority_expires_ms;
}
static bool mb_owner_postprepare_time(const struct mb_state *st,uint64_t before,
    uint64_t *start)
{
    if(start)*start=0;
    int64_t fresh=platform_time_monotonic_ms();
    if(!start||!before||fresh<=0||(uint64_t)fresh<before||
       (uint64_t)fresh>UINT64_MAX-UINT64_C(240000)||
       !mb_owner_start_authority_current(st,(uint64_t)fresh)){
        LOG_WARN("guest.owner","post-prepare start clock or current authority refused");
        return false;
    }
    *start=(uint64_t)fresh;return true;
}
bool zcl_mb_owner_called(struct mb_state *st, struct zcl_command_reply *reply)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&mb_public_owner_busy, &expected, true))
        return zcl_mb_boot_fail(reply, ZCL_COMMAND_EXIT_FAILED, "PUBLIC_OWNER_BUSY", "admit",
            "another called owner retains its invocation or cleanup obligation", MB_PATH);
    st->owner.admitted = true;
    int64_t now = platform_time_monotonic_ms();
    bool ok = now > 0 && (uint64_t)now <= UINT64_MAX - UINT64_C(240000) &&
        mb_owner_prepare(st, reply);
    uint64_t start=0;
    if (ok) ok = mb_owner_postprepare_time(st,(uint64_t)now,&start);
    if (ok) ok = mb_owner_start(st,start);
    struct guest_service_snapshot snapshot;
    int64_t observed = platform_time_monotonic_ms();
    bool have_snapshot = !ok && st->owner.manager && observed > 0 &&
        mesh_guest_service_manager_snapshot(st->owner.manager, (uint64_t)observed, &snapshot);
    if (!mb_owner_join(st, reply)) return false;
    if (!ok) return mb_owner_refusal(st, reply, have_snapshot ? &snapshot : NULL);
    (void)json_push_kv_bool(&reply->data, "public_fixture", st->owner.protected==NULL);
    if(st->owner.protected)(void)json_push_kv_bool(&reply->data,"protected_host",true);
    (void)json_push_kv_bool(&reply->data, "delivered32", true);
    (void)json_push_kv_bool(&reply->data, "attach_child_exit0", true);
    (void)json_push_kv_bool(&reply->data, "identity_ready", st->owner.identity_ready);
    if (!mb_owner_identity_reply(st, reply)) return false;
    (void)json_push_kv_bool(&reply->data, "joined", true);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    return true;
}

bool zcl_mb_owner_dispose(struct mb_state *st)
{
    if (st->owner.retained) return false;
    if(st->owner.protected){
        struct mb_protected_owner *p=st->owner.protected;
        /* Successful join is mandatory before freeing callback/cache custody. */
        if(st->owner.manager || !cached_destroy_after_quiescence(&p->provider))return false;
        free(p->owned_extension_path);free(p->owned_reserve_stage_path);free(p->owned_ready_stage_path);
        memory_cleanse(p,sizeof(*p));free(p);st->owner.protected=NULL;
    }
    platform_private_file_close(&st->owner.credential);
    platform_private_file_close(&st->owner.record);
    platform_private_file_close(&st->owner.volume);
    free(st->owner.owned_credential_path);
    free(st->owner.owned_record_path);
    free(st->owner.owned_volume_path);
    memory_cleanse(st->owner.line, sizeof(st->owner.line));
    if (st->owner.admitted) atomic_store(&mb_public_owner_busy, false);
    return true;
}
