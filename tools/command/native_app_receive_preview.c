/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Bind optional received-app preview inputs to saved source and existing Keep authority.
 */
#include "command/native_app_receive_preview.h"
#include "command/native_app_launch.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_selection.h"
#include "command/app_image.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "util/file_tree_ops.h"
#include "vcs/package_prepare.h"
#include "vcs/source_bundle.h"
#include "sha3/sha3.h"
#include "util/path_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct app_receive_preview {
    struct app_selection choice;
    struct app_selection kept;
    char state_dir[APP_LAUNCH_PATH_MAX];
    bool built, previewed, draft;
    enum zcl_package_copy_adoption trust;
};
static bool arp_same(const struct app_selection *a, const struct app_selection *b);
static bool arp_fail(struct zcl_command_reply *r, const char *code, const char *why)
{
    zcl_package_copy_fail(r, code, r->error.mutated, why, "app.receive preview");
    return false;
}
static bool arp_text(const struct json_value *d, const char *key, const char *want)
{
    const char *s = zcl_package_copy_str(d, key);
    return s && !strcmp(s, want);
}
static bool arp_bool(const struct json_value *d, const char *key, bool want)
{
    const struct json_value *v = json_get(d, key);
    return v && v->type == JSON_BOOL && json_get_bool(v) == want;
}
static bool arp_root(const struct json_value *d, const char *key, uint8_t out[32])
{
    const char *s = zcl_package_copy_str(d, key);
    return s && strlen(s) == 64 && zcl_hex_decode_lower(s, out, 32);
}
static bool arp_root_is(const struct json_value *d, const char *key, const uint8_t want[32])
{
    uint8_t got[32];
    return arp_root(d, key, got) && !memcmp(got, want, 32);
}
static const struct json_value *arp_envelope(const struct json_value *v, const char *command)
{
    if (!v || v->type != JSON_OBJ || !arp_text(v, "command", command) ||
        !arp_text(v, "status", "passed") || !arp_bool(v, "ok", true)) return NULL;
    const struct json_value *d = json_get(v, "data");
    return d && d->type == JSON_OBJ ? d : NULL;
}
static bool arp_tuple(const struct app_receive_preview *p, const struct json_value *d)
{
    return d && arp_text(d, "copy", p->choice.copy) &&
        arp_root_is(d, "version", p->choice.version) &&
        arp_root_is(d, "package_root", p->choice.package);
}
static void arp_route(struct app_selection *s, bool adopted)
{
    const char *domain = adopted ? "zcl.app.adopt.route.v1" : "zcl.app.receive.route.v1";
    struct sha3_256_ctx sha; uint8_t digest[32]; char hex[65];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain) + 1);
    sha3_256_write(&sha, s->fork, 32);
    /* NUL-delimited canonical paths cannot contain NUL: unambiguous framing. */
    sha3_256_write(&sha, (const uint8_t *)s->copy, strlen(s->copy) + 1);
    sha3_256_write(&sha, (const uint8_t *)s->datadir, strlen(s->datadir) + 1);
    sha3_256_finalize(&sha, digest); zcl_hex_encode(digest, 32, hex);
    (void)snprintf(s->app, sizeof(s->app), "kept:%s-%.18s", adopted ? "adopted" : "received", hex);
}
static bool arp_trust(const struct app_selection *s, const struct zcl_package_copy *copy,
    enum zcl_package_copy_adoption trust)
{
    struct zcl_package_adopt_record record;
    if (zcl_package_copy_adopted(s->datadir, copy, &record) != trust) return false;
    if (trust != ZCL_PACKAGE_COPY_ADOPTED) return true;
    struct vcs_package_release release; uint8_t id[32];
    return zcl_package_copy_find_release(s->datadir, s->parent, &release, id) == ZCL_PACKAGE_COPY_FOUND &&
        !memcmp(id, s->parent, 32) && !memcmp(record.package_root, release.package_root, 32) &&
        !memcmp(record.publisher_pubkey, release.publisher_pubkey, sizeof(record.publisher_pubkey));
}
static bool arp_history(const struct app_selection *s, enum zcl_package_copy_adoption trust,
    struct zcl_command_reply *r)
{
    struct zcl_package_copy copy = {0}; char version[65];
    zcl_hex_encode(s->version, 32, version);
    bool mutated = r->error.mutated;
    bool ok = zcl_package_copy_open_selected_as(s->copy, ZCL_PACKAGE_COPY_READ,
        &copy, r, "app.receive", version);
    r->error.mutated |= mutated;
    if (ok) {
        ok = !memcmp(copy.fork_version, s->fork, 32) &&
            !memcmp(copy.parent_release, s->parent, 32) &&
            arp_trust(s, &copy, trust);
        if (!ok) arp_fail(r, "PREVIEW_TRUST_CHANGED", "received copy history or owner trust changed");
    }
    zcl_package_copy_close(&copy);
    return ok;
}
static bool arp_received(struct app_receive_preview *p, const struct json_value *d,
    struct zcl_command_reply *r)
{
    struct zcl_package_copy copy = {0}; char version[65];
    zcl_hex_encode(p->choice.version, 32, version);
    bool mutated = r->error.mutated;
    bool ok = zcl_package_copy_open_selected_as(p->choice.copy, ZCL_PACKAGE_COPY_READ,
        &copy, r, "app.receive", version);
    r->error.mutated |= mutated;
    if (ok) {
        memcpy(p->choice.fork, copy.fork_version, 32);
        ok = !memcmp(copy.parent_release, p->choice.parent, 32) &&
            zcl_package_copy_adopted(p->choice.datadir, &copy, NULL) == ZCL_PACKAGE_COPY_RECEIVED_TRUSTED;
    }
    zcl_package_copy_close(&copy);
    if (!ok) return arp_fail(r, "PREVIEW_COPY_REFUSED", "exact received history and trust are required");
    struct vcs_package_release release; uint8_t id[32]; char publisher[67];
    if (zcl_package_copy_find_release(p->choice.datadir, p->choice.parent, &release, id) != ZCL_PACKAGE_COPY_FOUND)
        return arp_fail(r, "PREVIEW_RELEASE_MISSING", "received release is unavailable");
    zcl_hex_encode(release.publisher_pubkey, sizeof(release.publisher_pubkey), publisher);
    return (!memcmp(id, p->choice.parent, 32) && !memcmp(release.package_root, p->choice.package, 32) &&
        arp_text(d, "publisher_fingerprint", publisher)) ||
        arp_fail(r, "PREVIEW_RELEASE_MISMATCH", "received package and publisher must match persisted release");
}
static bool arp_locations(struct app_receive_preview *p, const struct json_value *d,
    const char *datadir, struct zcl_command_reply *r)
{
    const char *dir = zcl_package_copy_str(d, "destination");
    if (!dir || !datadir || !arp_text(d, "stage", "commit") || !arp_bool(d, "executed", false)) return arp_fail(r, "BAD_PREVIEW_INPUT", "received destination and datadir are required");
    bool ok = platform_directory_canonical_real(dir, p->choice.copy, sizeof(p->choice.copy)) &&
        platform_directory_canonical_real(datadir, p->choice.datadir, sizeof(p->choice.datadir)) &&
        arp_root(d, "version", p->choice.version) && arp_root(d, "release_id", p->choice.parent) &&
        arp_root(d, "package_root", p->choice.package);
    return ok || arp_fail(r, "BAD_PREVIEW_INPUT", "received paths or roots are invalid");
}
static bool arp_state(struct app_receive_preview *p, struct zcl_command_reply *r)
{
    struct app_launch_env env; char why[256] = {0};
    if (!app_launch_env_from_process(&env, why, sizeof(why)))
        return arp_fail(r, "PREVIEW_STATE_UNAVAILABLE", why);
    if (strlen(env.state_dir) >= sizeof(p->state_dir))
        return arp_fail(r, "PREVIEW_STATE_UNAVAILABLE", "selection state path is too long");
    memcpy(p->state_dir, env.state_dir, strlen(env.state_dir) + 1);
    return true;
}
static bool arp_state_valid(const struct app_receive_preview *p, struct zcl_command_reply *r, bool check_head)
{
    struct app_launch_env env; char why[256] = {0};
    if (!app_launch_env_from_process(&env, why, sizeof(why)) || strcmp(env.state_dir, p->state_dir))
        return arp_fail(r, "PREVIEW_STATE_CHANGED", "launcher selection environment changed during preview");
    if (!p->draft) return true;
    struct app_selection current;
    if (app_selection_load(p->state_dir, p->kept.app, &current) != APP_SELECTION_OK ||
        current.revision != p->kept.revision || !arp_same(&current, &p->kept))
        return arp_fail(r, "SELECTION_STALE", "the kept selection changed; review again");
    struct zcl_package_copy copy = {0}; char version[65];
    zcl_hex_encode(p->choice.version, 32, version);
    bool ok = zcl_package_copy_open_selected_as(p->choice.copy, ZCL_PACKAGE_COPY_READ,
        &copy, r, "app.library", version);
    if (ok) ok = (!check_head || !memcmp(copy.head_version, p->choice.version, 32)) &&
        !memcmp(copy.fork_version, p->kept.fork, 32) &&
        !memcmp(copy.parent_release, p->kept.parent, 32) && arp_trust(&p->choice, &copy, p->trust);
    zcl_package_copy_close(&copy);
    return ok || arp_fail(r, "DRAFT_STALE", "the draft or its owner trust changed; review again");
}
static bool arp_state_current(const struct app_receive_preview *p, struct zcl_command_reply *r)
{
    return arp_state_valid(p, r, true);
}
bool app_receive_preview_current(const struct app_receive_preview *p, struct zcl_command_reply *r)
{
    return p && arp_state_current(p, r);
}
bool app_receive_preview_create(const struct json_value *d, const char *datadir,
    struct app_receive_preview **out, struct zcl_command_reply *r)
{
    if (!out) return arp_fail(r, "BAD_PREVIEW_INPUT", "preview output is required");
    *out = NULL;
    struct app_receive_preview *p = zcl_calloc(1, sizeof(*p), "app-receive-preview");
    if (!p) return arp_fail(r, "OUT_OF_MEMORY", "cannot allocate received preview identity");
    if (!arp_locations(p, d, datadir, r) || !arp_received(p, d, r) || !arp_state(p, r)) {
        free(p); return false;
    }
    p->trust = ZCL_PACKAGE_COPY_RECEIVED_TRUSTED;
    arp_route(&p->choice, false); *out = p; return true;
}
/* Adoption's package is the original release, not the personalized successor. */
static bool arp_adopted_locations(struct app_receive_preview *p,
    const struct json_value *d, const char *datadir, struct zcl_command_reply *r)
{
    const char *copy = zcl_package_copy_str(d, "copy");
    if (!copy || !datadir || !arp_bool(d, "adopted", true) || !arp_bool(d, "executed", false))
        return arp_fail(r, "BAD_PREVIEW_INPUT", "committed adopted copy and datadir are required");
    bool ok = platform_directory_canonical_real(copy, p->choice.copy, sizeof(p->choice.copy)) &&
        platform_directory_canonical_real(datadir, p->choice.datadir, sizeof(p->choice.datadir)) &&
        arp_root(d, "root_commit", p->choice.fork) && arp_root(d, "release_root", p->choice.parent) &&
        arp_root(d, "version", p->choice.version);
    return ok || arp_fail(r, "BAD_PREVIEW_INPUT", "adopted paths or saved roots are invalid");
}
static bool arp_adopted_release(const struct app_receive_preview *p,
    const struct json_value *d, struct zcl_command_reply *r)
{
    struct vcs_package_release release; uint8_t id[32];
    if (zcl_package_copy_find_release(p->choice.datadir, p->choice.parent, &release, id) != ZCL_PACKAGE_COPY_FOUND)
        return arp_fail(r, "PREVIEW_RELEASE_MISSING", "adopted release is unavailable");
    return (!memcmp(id, p->choice.parent, 32) && arp_root_is(d, "package_root", release.package_root)) ||
        arp_fail(r, "PREVIEW_RELEASE_MISMATCH", "original adoption package must match the persisted release");
}
static bool arp_adopted_prepare(struct app_receive_preview *p,
    const struct zcl_package_copy *copy, const char *scratch, struct zcl_command_reply *r)
{
    if (vcs_tree_materialize_readonly_disposable(p->choice.copy, copy->selected_tree,
        scratch, VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0) != VCS_OK)
        return arp_fail(r, "PREVIEW_SOURCE_INVALID", "saved personal source could not be reconstructed");
    struct vcs_package_prepared prepared; char detail[256];
    vcs_package_prepared_init(&prepared);
    enum vcs_package_prepare_error err = vcs_package_prepare_content(scratch, &prepared, detail, sizeof(detail));
    if (err == VCS_PACKAGE_PREPARE_OK) memcpy(p->choice.package, prepared.package_root, 32);
    vcs_package_prepared_free(&prepared);
    return err == VCS_PACKAGE_PREPARE_OK ||
        arp_fail(r, "PREVIEW_PACKAGE_INVALID", "saved personal source does not derive a valid full package");
}
static bool arp_adopted_derive(struct app_receive_preview *p, struct zcl_command_reply *r)
{
    struct zcl_package_copy copy = {0}; char version[65], scratch[PLATFORM_TEMP_PATH_MAX] = {0};
    zcl_hex_encode(p->choice.version, 32, version);
    bool mutated = r->error.mutated;
    bool ok = zcl_package_copy_open_selected_as(p->choice.copy, ZCL_PACKAGE_COPY_READ,
        &copy, r, "app.adopt", version);
    r->error.mutated |= mutated;
    if (ok) {
        ok = !memcmp(copy.fork_version, p->choice.fork, 32) &&
            !memcmp(copy.parent_release, p->choice.parent, 32) &&
            arp_trust(&p->choice, &copy, p->trust);
        if (!ok) arp_fail(r, "PREVIEW_COPY_REFUSED", "exact adopted history and owner grant are required");
    }
    if (ok && !platform_temp_directory_create("z23-adopt-preview-", scratch, sizeof(scratch)))
        ok = arp_fail(r, "PREVIEW_SCRATCH_FAILED", "cannot create private source scratch");
    if (ok) ok = arp_adopted_prepare(p, &copy, scratch, r);
    zcl_package_copy_close(&copy); /* No reader lock survives into a worker. */
    if (scratch[0] && !zcl_tree_remove(scratch).ok) {
        zcl_package_copy_fail(r, "PREVIEW_CLEANUP_FAILED", true,
            "Private source scratch remains; retain and inspect it before retrying.", scratch);
        return false;
    }
    return ok;
}
bool app_receive_preview_create_adopted(const struct json_value *d, const char *datadir,
    struct app_receive_preview **out, struct zcl_command_reply *r)
{
    if (!out) return arp_fail(r, "BAD_PREVIEW_INPUT", "preview output is required");
    *out = NULL;
    struct app_receive_preview *p = zcl_calloc(1, sizeof(*p), "app-adopted-preview");
    if (!p) return arp_fail(r, "OUT_OF_MEMORY", "cannot allocate adopted preview identity");
    p->trust = ZCL_PACKAGE_COPY_ADOPTED;
    if (!arp_adopted_locations(p, d, datadir, r) || !arp_adopted_release(p, d, r) ||
        !arp_adopted_derive(p, r) || !arp_state(p, r)) { free(p); return false; }
    arp_route(&p->choice, true); *out = p; return true;
}

static bool arp_draft_head(const struct app_selection *s, uint8_t head[32],
    enum zcl_package_copy_adoption *trust, struct zcl_command_reply *r)
{
    struct zcl_package_copy copy = {0}; char version[65];
    zcl_hex_encode(s->version, 32, version);
    bool ok = zcl_package_copy_open_selected_as(s->copy, ZCL_PACKAGE_COPY_READ,
        &copy, r, "app.library", version);
    if (ok) {
        *trust = zcl_package_copy_adopted(s->datadir, &copy, NULL);
        ok = (*trust == ZCL_PACKAGE_COPY_ADOPTED || *trust == ZCL_PACKAGE_COPY_RECEIVED_TRUSTED) &&
            !memcmp(copy.fork_version, s->fork, 32) && !memcmp(copy.parent_release, s->parent, 32) &&
            !memcmp(copy.selected_version, s->version, 32) && memcmp(copy.head_version, s->version, 32) &&
            arp_trust(s, &copy, *trust);
        if (ok) memcpy(head, copy.head_version, 32);
    }
    zcl_package_copy_close(&copy);
    return ok;
}
bool app_saved_draft_available(const struct app_selection *selection)
{
    if (!selection) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    uint8_t head[32]; enum zcl_package_copy_adoption trust;
    bool ok = arp_draft_head(selection, head, &trust, &reply);
    zcl_command_reply_free(&reply); return ok;
}
bool app_saved_draft_head(const struct app_selection *selection, uint8_t head[32],
    struct zcl_command_reply *r)
{
    enum zcl_package_copy_adoption trust;
    if (!selection || !head || !r) return false;
    if (!arp_draft_head(selection, head, &trust, r))
        return arp_fail(r, "DRAFT_UNAVAILABLE", "no verified unkept version is available");
    return true;
}
static bool arp_draft_prepare(struct app_receive_preview *p, const struct app_selection *selection,
    const uint8_t expected_head[32], struct zcl_command_reply *r)
{
    bool ok = arp_draft_head(selection, p->choice.version, &p->trust, r);
    if (ok && memcmp(p->choice.version, expected_head, 32))
        ok = arp_fail(r, "DRAFT_STALE", "the draft changed; review again");
    if (ok) ok = arp_state(p, r) && arp_state_current(p, r) && arp_adopted_derive(p, r) && arp_state_current(p, r);
    if (!ok && r->status == ZCL_COMMAND_STATUS_PASSED)
        (void)arp_fail(r, "DRAFT_UNAVAILABLE", "no verified unkept version is available");
    return ok;
}
bool app_saved_draft_preview_create(const struct app_selection *selection,
    const uint8_t expected_head[32], struct app_receive_preview **out, struct zcl_command_reply *r)
{
    if (!selection || !expected_head || !out || selection->revision == 0 || selection->revision > INT64_MAX)
        return arp_fail(r, "BAD_PREVIEW_INPUT", "a kept selection and reviewed draft are required");
    *out = NULL;
    struct app_receive_preview *p = zcl_calloc(1, sizeof(*p), "app-draft-preview");
    if (!p) return arp_fail(r, "OUT_OF_MEMORY", "cannot allocate draft preview identity");
    p->kept = p->choice = *selection; p->draft = true;
    if (!arp_draft_prepare(p, selection, expected_head, r)) { free(p); return false; }
    *out = p; return true;
}

bool app_receive_preview_build_input(const struct app_receive_preview *p, struct json_value *out)
{
    json_init(out); json_set_object(out);
    return p && json_push_kv_str(out, "copy", p->choice.copy) &&
        json_push_kv_str(out, "datadir", p->choice.datadir) && zcl_package_copy_push_root(out, "version", p->choice.version);
}
bool app_receive_preview_confirm_input(const struct app_receive_preview *p,
    const struct json_value *envelope, struct json_value *out, struct zcl_command_reply *r)
{
    json_init(out);
    const struct json_value *d = arp_envelope(envelope, "app.build"); uint8_t plan[32];
    if (!p || !arp_tuple(p, d) || !arp_text(d, "stage", "plan") || !arp_root(d, "plan_id", plan))
        return arp_fail(r, "PREVIEW_PLAN_MISMATCH", "build plan does not match the received saved version");
    if (!arp_history(&p->choice, p->trust, r)) return false;
    return (app_receive_preview_build_input(p, out) && zcl_package_copy_push_root(out, "plan_id", plan) &&
        json_push_kv_bool(out, "confirm", true)) || arp_fail(r, "OUT_OF_MEMORY", "cannot assemble build confirmation");
}
static bool arp_record(const struct app_selection *s, struct zcl_command_reply *r)
{
    char store[APP_SELECTION_PATH_MAX + 32]; struct app_image_build rec; bool hit = false;
    uint8_t id[32];
    if (!zcl_path_join(store, sizeof(store), s->datadir, "app_build/records"))
        return arp_fail(r, "PREVIEW_BUILD_MISMATCH", "build store path is too long");
    struct zcl_result result = app_image_build_load(store, s->package, s->env, s->dependencies, &rec, &hit);
    if (!result.ok || !hit || !app_image_build_id(&rec, id).ok ||
        memcmp(id, s->record, 32) || memcmp(rec.image_sha3, s->image, 32))
        return arp_fail(r, "PREVIEW_BUILD_MISMATCH", "received build tuple has no matching valid record");
    return true;
}
bool app_receive_preview_bind_build(struct app_receive_preview *p,
    const struct json_value *envelope, struct zcl_command_reply *r)
{
    if (!p) return arp_fail(r, "BAD_PREVIEW_INPUT", "preview context is required");
    p->built = false; p->previewed = false;
    const struct json_value *d = arp_envelope(envelope, "app.build");
    struct app_selection s = p->choice;
    if (!arp_tuple(p, d) || !arp_text(d, "stage", "commit") || !arp_bool(d, "executed", false))
        return arp_fail(r, "PREVIEW_BUILD_MISMATCH", "successful saved-version build commit required");
    if (!arp_root(d, "env_root", s.env) || !arp_root(d, "dependency_root", s.dependencies) ||
        !arp_root(d, "record_id", s.record) || !arp_root(d, "image_sha3", s.image))
        return arp_fail(r, "PREVIEW_BUILD_MISMATCH", "build identity is incomplete");
    if (!arp_history(&s, p->trust, r) || !arp_record(&s, r)) return false;
    p->choice = s; p->built = true; return true;
}
bool app_receive_preview_open_input(const struct app_receive_preview *p, struct json_value *out)
{
    json_init(out);
    if (!p || !p->built) return false;
    return app_receive_preview_build_input(p, out) && json_push_kv_str(out, "name", p->choice.app) &&
        zcl_package_copy_push_root(out, "env_root", p->choice.env) && zcl_package_copy_push_root(out, "dependency_root", p->choice.dependencies) &&
        zcl_package_copy_push_root(out, "record_id", p->choice.record) && zcl_package_copy_push_root(out, "image_sha3", p->choice.image) &&
        json_push_kv_bool(out, "accept_execution", true);
}
static bool arp_open_tuple(const struct app_receive_preview *p, const struct json_value *d)
{
    return arp_tuple(p, d) && arp_text(d, "datadir", p->choice.datadir) && arp_text(d, "name", p->choice.app) &&
        arp_root_is(d, "env_root", p->choice.env) && arp_root_is(d, "dependency_root", p->choice.dependencies) &&
        arp_root_is(d, "record_id", p->choice.record) && arp_root_is(d, "image_sha3", p->choice.image);
}
static bool arp_process(const struct json_value *d)
{
    const struct json_value *pid = json_get(d, "pid");
    const char *token = zcl_package_copy_str(d, "start_token");
    if (!pid || pid->type != JSON_INT || json_get_int(pid) <= 0 || !token) return false;
    uint64_t number = 0;
    for (const char *s = token; *s; ++s) {
        if (*s < '0' || *s > '9' || number > (UINT64_MAX - (unsigned)(*s - '0')) / 10) return false;
        number = number * 10 + (unsigned)(*s - '0');
    }
    return number != 0 && (arp_text(d, "mapped_proof", "fexecve_inode") ||
        arp_text(d, "mapped_proof", "proc_exe_triple") || arp_text(d, "mapped_proof", "cdhash_suspended"));
}
bool app_receive_preview_bind_preview(struct app_receive_preview *p,
    const struct json_value *envelope, struct zcl_command_reply *r)
{
    if (!p) return arp_fail(r, "BAD_PREVIEW_INPUT", "preview context is required");
    p->previewed = false;
    const struct json_value *d = arp_envelope(envelope, "app.open");
    if (!p->built || !arp_open_tuple(p, d) || !arp_text(d, "status", "opened") ||
        !arp_bool(d, "ready", true) || !arp_bool(d, "exited", false) || !arp_text(d, "ready_basis", "alive"))
        return arp_fail(r, "PREVIEW_NOT_READY", "exact selected app must report successful alive preview");
    if (!arp_process(d)) return arp_fail(r, "PREVIEW_NOT_READY", "preview process identity is missing or unsupported");
    if (!arp_state_current(p, r) || !arp_history(&p->choice, p->trust, r) || !arp_record(&p->choice, r)) return false;
    p->previewed = true; return true;
}
static bool arp_same(const struct app_selection *a, const struct app_selection *b)
{
    return !strcmp(a->app, b->app) && !strcmp(a->copy, b->copy) && !strcmp(a->datadir, b->datadir) &&
        !memcmp(a->fork, b->fork, 32) && !memcmp(a->parent, b->parent, 32) &&
        !memcmp(a->version, b->version, 32) && !memcmp(a->package, b->package, 32) &&
        !memcmp(a->env, b->env, 32) && !memcmp(a->dependencies, b->dependencies, 32) &&
        !memcmp(a->record, b->record, 32) && !memcmp(a->image, b->image, 32);
}
static enum app_receive_preview_keep_state arp_draft_keep(const struct app_receive_preview *p,
    const struct app_selection *current, enum app_selection_result loaded, struct json_value *out,
    struct zcl_command_reply *r)
{
    if (loaded != APP_SELECTION_OK || current->revision != p->kept.revision || !arp_same(current, &p->kept)) {
        arp_fail(r, "SELECTION_STALE", "the kept selection changed; review again");
        return APP_RECEIVE_PREVIEW_KEEP_REFUSED;
    }
    if (app_receive_preview_open_input(p, out) && json_push_kv_int(out, "expected_revision", (int64_t)p->kept.revision))
        return APP_RECEIVE_PREVIEW_KEEP_NEW;
    arp_fail(r, "OUT_OF_MEMORY", "cannot assemble Keep request");
    return APP_RECEIVE_PREVIEW_KEEP_REFUSED;
}
enum app_receive_preview_keep_state app_receive_preview_keep_input(
    const struct app_receive_preview *p, struct json_value *out, struct zcl_command_reply *r)
{
    json_init(out);
    if (!p || !p->previewed) {
        arp_fail(r, "PREVIEW_REQUIRED", "a successful exact-image preview must precede Keep");
        return APP_RECEIVE_PREVIEW_KEEP_REFUSED;
    }
    if (!arp_state_valid(p, r, !p->draft) || !arp_history(&p->choice, p->trust, r) || !arp_record(&p->choice, r)) return APP_RECEIVE_PREVIEW_KEEP_REFUSED;
    struct app_selection current;
    enum app_selection_result loaded = app_selection_load(p->state_dir, p->choice.app, &current);
    if (p->draft) return arp_draft_keep(p, &current, loaded, out, r);
    if (loaded == APP_SELECTION_OK) {
        if (arp_same(&p->choice, &current)) return APP_RECEIVE_PREVIEW_KEEP_SAME;
        arp_fail(r, "PREVIEW_ROUTE_COLLISION", "received route already belongs to a different choice");
        return APP_RECEIVE_PREVIEW_KEEP_REFUSED;
    }
    if (loaded != APP_SELECTION_ABSENT) {
        arp_fail(r, "SELECTION_UNREADABLE", "received route cannot be read safely");
        return APP_RECEIVE_PREVIEW_KEEP_REFUSED;
    }
    if (app_receive_preview_open_input(p, out) && json_push_kv_int(out, "expected_revision", 0))
        return APP_RECEIVE_PREVIEW_KEEP_NEW;
    arp_fail(r, "OUT_OF_MEMORY", "cannot assemble Keep request");
    return APP_RECEIVE_PREVIEW_KEEP_REFUSED;
}
void app_receive_preview_close(struct app_receive_preview *p) { free(p); }
