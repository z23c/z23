/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Local reproduction evidence for package POINTER publication. */

#include "config/boot_zcode_dht_publish_gate.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "vcs/package_index.h"
#include "vcs/package_release.h"
#include "vcs/package_reproduce.h"
#include "vcs/package_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Same ok/code/message refusal shape as rpc_error in boot_zcode_dht_rpc.c so
 * the wire-visible refusal is byte-identical to every other RPC refusal. */
static void gate_error(struct json_value *result, const char *code,
                       const char *message) {
  json_set_object(result);
  json_push_kv_bool(result, "ok", false);
  json_push_kv_str(result, "code", code);
  json_push_kv_str(result, "message", message);
}

/* Bounded whole-file read for the persisted release envelope (allocates
 * *out; caller frees). False when missing, unreadable, empty, or over cap
 * (trailing bytes = not the exact object). */
static bool gate_read_object(const char *path, size_t cap, uint8_t **out,
                             size_t *out_len) {
  *out = NULL;
  *out_len = 0;
  FILE *f = fopen(path, "rb");
  if (!f)
    return false;
  uint8_t *buf = zcl_malloc(cap, "gate_read_object");
  if (!buf) {
    fclose(f);
    return false;
  }
  size_t len = fread(buf, 1, cap, f);
  bool ok = !ferror(f) && feof(f) && len > 0;
  fclose(f);
  if (!ok) {
    free(buf);
    return false;
  }
  *out = buf;
  *out_len = len;
  return true;
}

/* Package-pointer reproduction gate. A zclassic23.package POINTER record
 * claims "this exact package_root is discoverable and fetchable from me".
 * That claim is only honest when this node's own store holds a committed
 * release naming the root AND the store's receipts directory evidences
 * reproduction: >= 2 distinct byte-identical installable build receipts for
 * the exact (package_root, recipe_root) pair the signed release commits
 * (vcs_package_reproduce_scan). Everything else refuses BEFORE a plan token
 * exists, so plan and commit are gated identically. Returns true when the
 * publish may proceed; on refusal the exact named code is in result. */
bool boot_zcode_dht_package_pointer_publish_gate(
    const struct vcs_zcode_dht_publish_spec *spec,
    struct json_value *result) {
  struct vcs_package_store *store = vcs_package_store_global();
  if (!store) {
    gate_error(result, "NO_PACKAGE_STORE",
               "package hosting is disabled on this node; enable -packagehost=1"
               " and install the package with zcode use before publishing its"
               " pointer");
    return false;
  }
  const char *zcode_dir = vcs_package_store_root_dir(store);
  struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
  if (!index) {
    LOG_ERROR("net.zcode_dht", "publish gate: package index build failed for %s",
              zcode_dir);
    gate_error(result, "PACKAGE_INDEX_UNAVAILABLE",
               "the local package index could not be rebuilt from the store");
    return false;
  }
  const struct vcs_package_index_entry *entry =
      vcs_package_index_find_root(index, spec->semantic_root);
  if (!entry) {
    vcs_package_index_free(index);
    gate_error(result, "UNKNOWN_PACKAGE",
               "no locally committed release names this package root");
    return false;
  }
  char path[4400];
  int n = snprintf(path, sizeof(path), "%s/releases/%s", zcode_dir,
                   entry->release_id_hex);
  uint8_t *wire = NULL;
  size_t wire_len = 0;
  struct vcs_package_release release;
  bool read_ok =
      n > 0 && (size_t)n < sizeof(path) &&
      gate_read_object(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &wire,
                       &wire_len) &&
      vcs_package_release_parse(wire, wire_len, &release) ==
          VCS_PACKAGE_RELEASE_OK;
  free(wire);
  vcs_package_index_free(index);
  if (!read_ok) {
    gate_error(result, "RELEASE_UNREADABLE",
               "the persisted release envelope for this package root is missing"
               " or unparseable");
    return false;
  }
  char receipts_dir[4400];
  n = snprintf(receipts_dir, sizeof(receipts_dir), "%s/receipts", zcode_dir);
  struct vcs_reproduce_report report;
  bool scanned = n > 0 && (size_t)n < sizeof(receipts_dir) &&
                 vcs_package_reproduce_scan(receipts_dir, spec->semantic_root,
                                            release.recipe_root, &report);
  if (!scanned || !report.reproduced) {
    gate_error(result, "REPRODUCTION_NOT_EVIDENCED",
               "pointer publication requires reproduction evidence in the local"
               " store: at least 2 distinct byte-identical installable build"
               " receipts for this exact package and recipe root; install the"
               " package with zcode use, run zcode package reproduce, then"
               " republish");
    return false;
  }
  return true;
}
