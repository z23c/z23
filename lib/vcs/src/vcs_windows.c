/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: expose fail-closed Windows behavior for unavailable ZVCS verbs. */
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

#if defined(_WIN32)
#include <stdlib.h>
#include <string.h>

struct vcs_repo {
    char root[4096];
    struct vcs_index *idx;
};

bool vcs_tree_load(const char *repo_root, const uint8_t tree_hash[32],
                   struct vcs_manifest *out)
{
    if (!repo_root || !tree_hash || !out) return false;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw(repo_root, tree_hash, &wire, &wire_len) != 0)
        return false;
    bool ok = vcs_manifest_parse(wire, wire_len, out);
    free(wire);
    uint8_t checked[32];
    if (!ok || !vcs_manifest_tree_hash(out, checked) ||
        memcmp(checked, tree_hash, 32) != 0) {
        if (ok) vcs_manifest_free(out);
        return false;
    }
    return true;
}
struct vcs_repo *vcs_open(const char *root) { (void)root; return NULL; }
void vcs_close(struct vcs_repo *repo) { free(repo); }
struct vcs_index *vcs_repo_index(struct vcs_repo *repo)
{ return repo ? repo->idx : NULL; }
const char *vcs_repo_root(struct vcs_repo *repo)
{ return repo ? repo->root : NULL; }
static int vcs_windows_refuse_hash(uint8_t out[32])
{ if (out) memset(out, 0, 32); return VCS_REFUSED; }
int vcs_tree_capture(struct vcs_repo *repo, uint8_t out[32])
{ (void)repo; return vcs_windows_refuse_hash(out); }
int vcs_tree_capture_path(const char *root, uint8_t out[32])
{ (void)root; return vcs_windows_refuse_hash(out); }
int vcs_tree_capture_into(const char *scan, const char *store, uint8_t out[32])
{ (void)scan; (void)store; return vcs_windows_refuse_hash(out); }
int vcs_snapshot(struct vcs_repo *repo, const struct vcs_snapshot_meta *meta,
                 uint8_t out[32])
{ (void)repo; (void)meta; return vcs_windows_refuse_hash(out); }
int vcs_status(struct vcs_repo *repo, vcs_diff_cb cb, void *user,
               size_t *changes)
{ (void)repo; (void)cb; (void)user; if (changes) *changes = 0; return VCS_REFUSED; }
int vcs_log(struct vcs_repo *repo, size_t limit, vcs_log_cb cb, void *user)
{ (void)repo; (void)limit; (void)cb; (void)user; return VCS_REFUSED; }
int vcs_revert(struct vcs_repo *repo, const uint8_t target[32],
               const struct vcs_revert_relink_ops *relink, uint8_t out[32])
{ (void)repo; (void)target; (void)relink; return vcs_windows_refuse_hash(out); }
#else
typedef int vcs_windows_requires_a_translation_unit;
#endif
