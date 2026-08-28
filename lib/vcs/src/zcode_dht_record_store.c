/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded canonical persistence for signed ZCODE DHT records. */

#include "vcs/zcode_dht_record_store.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/write_all.h"
#include "vcs/zcode_dht_identity.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RECORD_STORE_VERSION 1u
#define RECORD_STORE_DIGEST_DOMAIN "zcl.zcode.dht.record-store.v1"
#define RECORD_STREAM_DIGEST_DOMAIN "zcl.zcode.dht.record-stream.v1"

static const uint8_t record_store_magic[8] = {'Z', 'C', 'D', 'H',
                                              'T', 'S', 0x0d, 0x0a};

struct record_store_entry {
  struct vcs_zcode_dht_record record;
  uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
};

struct vcs_zcode_dht_record_store {
  uint8_t network_genesis[32];
  size_t count;
  struct record_store_entry *entries;
};

static _Atomic uint64_t g_record_store_temp_sequence;

static enum vcs_zcode_dht_record_store_result store_error(
    char *out, size_t capacity, enum vcs_zcode_dht_record_store_result result,
    const char *message)
{
  if (out && capacity)
    (void)snprintf(out, capacity, "%s", message ? message : "record store");
  return result;
}

const char *vcs_zcode_dht_record_store_result_string(
    enum vcs_zcode_dht_record_store_result result)
{
  switch (result) {
  case VCS_ZCODE_DHT_RECORD_STORE_OK: return "ok";
  case VCS_ZCODE_DHT_RECORD_STORE_ADDED: return "added";
  case VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE: return "duplicate";
  case VCS_ZCODE_DHT_RECORD_STORE_CONFLICT: return "conflict";
  case VCS_ZCODE_DHT_RECORD_STORE_STALE: return "stale-sequence";
  case VCS_ZCODE_DHT_RECORD_STORE_EXPIRED: return "expired";
  case VCS_ZCODE_DHT_RECORD_STORE_INVALID: return "invalid";
  case VCS_ZCODE_DHT_RECORD_STORE_ROOT_CAP: return "root-cap";
  case VCS_ZCODE_DHT_RECORD_STORE_PROVIDER_CAP: return "provider-cap";
  case VCS_ZCODE_DHT_RECORD_STORE_CONFLICT_CAP: return "conflict-cap";
  case VCS_ZCODE_DHT_RECORD_STORE_GLOBAL_CAP: return "global-cap";
  case VCS_ZCODE_DHT_RECORD_STORE_NO_SLOT:
    return "no free publication slot";
  case VCS_ZCODE_DHT_RECORD_STORE_SCOPE:
    return "agent scope authority is unavailable";
  case VCS_ZCODE_DHT_RECORD_STORE_IO: return "io";
  case VCS_ZCODE_DHT_RECORD_STORE_CORRUPT: return "corrupt";
  }
  return "unknown";
}

struct vcs_zcode_dht_record_store *vcs_zcode_dht_record_store_create(
    const uint8_t network_genesis[32])
{
  if (!network_genesis)
    return NULL;
  struct vcs_zcode_dht_record_store *store =
      zcl_calloc(1, sizeof(*store), "dht.record_store");
  if (!store)
    return NULL;
  store->entries = zcl_calloc(VCS_ZCODE_DHT_RECORD_STORE_MAX_RECORDS,
                              sizeof(*store->entries),
                              "dht.record_store.entries");
  if (!store->entries) {
    free(store);
    return NULL;
  }
  memcpy(store->network_genesis, network_genesis, 32);
  return store;
}

struct vcs_zcode_dht_record_store *vcs_zcode_dht_record_store_clone(
    const struct vcs_zcode_dht_record_store *store)
{
  if (!store)
    return NULL;
  struct vcs_zcode_dht_record_store *copy =
      vcs_zcode_dht_record_store_create(store->network_genesis);
  if (!copy)
    return NULL;
  copy->count = store->count;
  memcpy(copy->entries, store->entries,
         store->count * sizeof(*store->entries));
  return copy;
}

void vcs_zcode_dht_record_store_free(
    struct vcs_zcode_dht_record_store *store)
{
  if (!store)
    return;
  free(store->entries);
  free(store);
}

static const uint8_t *record_root(const struct vcs_zcode_dht_record *record)
{
  return record->kind == VCS_ZCODE_DHT_RECORD_POINTER
             ? record->semantic_root
             : record->transport_root;
}

bool vcs_zcode_dht_record_stream_equal(const struct vcs_zcode_dht_record *a,
                                       const struct vcs_zcode_dht_record *b)
{
  if (a->kind != b->kind ||
      strcmp(a->namespace_name, b->namespace_name) != 0 ||
      memcmp(a->network_genesis, b->network_genesis, 32) != 0 ||
      memcmp(a->provider_node_id, b->provider_node_id, 32) != 0 ||
      memcmp(a->delegation.doc.master_pubkey,
             b->delegation.doc.master_pubkey, 32) != 0)
    return false;
  return memcmp(record_root(a), record_root(b), 32) == 0;
}

static int entry_compare(const void *left, const void *right)
{
  const struct record_store_entry *a = left;
  const struct record_store_entry *b = right;
  return memcmp(a->wire, b->wire, VCS_ZCODE_DHT_RECORD_WIRE_BYTES);
}

/* Drop every record whose expiry has passed, in place and order-preserving
 * (whole elements move, so the canonical wire sort load() verifies is kept),
 * returning how many rows were freed. This mirrors exactly what load()
 * already prunes on restart — same predicate, no format or digest change —
 * so reclaiming early is semantically "reload happened now". */
size_t vcs_zcode_dht_record_store_collect(
    struct vcs_zcode_dht_record_store *store, uint64_t now_unix)
{
  if (!store)
    return 0;
  size_t write_index = 0;
  for (size_t i = 0; i < store->count; i++) {
    if (now_unix >= store->entries[i].record.expiry)
      continue; /* counted by subtraction below */
    store->entries[write_index++] = store->entries[i];
  }
  size_t removed = store->count - write_index;
  store->count = write_index;
  return removed;
}

enum vcs_zcode_dht_record_store_result vcs_zcode_dht_record_store_put(
    struct vcs_zcode_dht_record_store *store,
    const struct vcs_zcode_dht_record *record, uint64_t now_unix)
{
  if (!store || !record ||
      memcmp(store->network_genesis, record->network_genesis, 32) != 0)
    return VCS_ZCODE_DHT_RECORD_STORE_INVALID;
  if (now_unix < record->not_before)
    return VCS_ZCODE_DHT_RECORD_STORE_INVALID;
  if (now_unix >= record->expiry)
    return VCS_ZCODE_DHT_RECORD_STORE_EXPIRED;
  uint8_t wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
  if (vcs_zcode_dht_record_encode(record, wire) !=
      VCS_ZCODE_DHT_RECORD_OK)
    return VCS_ZCODE_DHT_RECORD_STORE_INVALID;

  /* One pass gathers the complete admission decision over the same live
   * set load() would rebuild at now_unix. Expired rows influence neither
   * sequence/conflict verdicts nor capacity. Each live counter carries its
   * own would-be-superseded drop so post-removal arithmetic needs no second
   * scan. Every same-stream-older row shares root and provider with the
   * incoming record (stream equality implies both), so one superseded flag
   * feeds all three drops. */
  uint64_t max_sequence = 0;
  size_t conflicts = 0;
  size_t glob_live = 0, glob_drop = 0;
  size_t root_live = 0, root_drop = 0;
  size_t provider_live = 0, provider_drop = 0;
  for (size_t i = 0; i < store->count; i++) {
    const struct record_store_entry *entry = &store->entries[i];
    const struct vcs_zcode_dht_record *existing = &entry->record;
    if (now_unix >= existing->expiry)
      continue;
    bool same_stream =
        vcs_zcode_dht_record_stream_equal(existing, record);
    bool superseded = false;
    if (same_stream) {
      if (existing->sequence > max_sequence)
        max_sequence = existing->sequence;
      if (existing->sequence == record->sequence) {
        conflicts++;
        if (memcmp(entry->wire, wire, sizeof(wire)) == 0)
          return VCS_ZCODE_DHT_RECORD_STORE_DUPLICATE;
      }
      superseded = existing->sequence < record->sequence;
    }
    glob_live++;
    if (memcmp(record_root(existing), record_root(record), 32) == 0) {
      root_live++;
      if (superseded)
        root_drop++;
    }
    if (memcmp(existing->provider_node_id, record->provider_node_id,
               32) == 0) {
      provider_live++;
      if (superseded)
        provider_drop++;
    }
    if (superseded)
      glob_drop++;
  }
  if (max_sequence > record->sequence)
    return VCS_ZCODE_DHT_RECORD_STORE_STALE;
  if (max_sequence == record->sequence &&
      conflicts >= VCS_ZCODE_DHT_RECORD_STORE_MAX_CONFLICTS)
    return VCS_ZCODE_DHT_RECORD_STORE_CONFLICT_CAP;
  bool newer = max_sequence && record->sequence > max_sequence;
  if (glob_live - (newer ? glob_drop : 0) >=
      VCS_ZCODE_DHT_RECORD_STORE_MAX_RECORDS)
    return VCS_ZCODE_DHT_RECORD_STORE_GLOBAL_CAP;
  if (root_live - (newer ? root_drop : 0) >=
      VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT)
    return VCS_ZCODE_DHT_RECORD_STORE_ROOT_CAP;
  if (provider_live - (newer ? provider_drop : 0) >=
      VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_PROVIDER)
    return VCS_ZCODE_DHT_RECORD_STORE_PROVIDER_CAP;

  /* Physical reclaim mirrors the live-capacity view: expired rows go when
   * this admission lands, so a stored image after any successful put
   * matches what a reload would have produced. */
  size_t write_index = 0;
  for (size_t i = 0; i < store->count; i++) {
    struct record_store_entry *entry = &store->entries[i];
    bool remove = now_unix >= entry->record.expiry ||
                  (newer &&
                   vcs_zcode_dht_record_stream_equal(&entry->record,
                                                     record) &&
                   entry->record.sequence < record->sequence);
    if (!remove)
      store->entries[write_index++] = *entry;
  }
  store->count = write_index;
  struct record_store_entry *entry = &store->entries[store->count++];
  entry->record = *record;
  memcpy(entry->wire, wire, sizeof(entry->wire));
  qsort(store->entries, store->count, sizeof(*store->entries), entry_compare);
  return conflicts ? VCS_ZCODE_DHT_RECORD_STORE_CONFLICT
                   : VCS_ZCODE_DHT_RECORD_STORE_ADDED;
}

size_t vcs_zcode_dht_record_store_count(
    const struct vcs_zcode_dht_record_store *store)
{
  return store ? store->count : 0;
}

size_t vcs_zcode_dht_record_store_query(
    const struct vcs_zcode_dht_record_store *store,
    enum vcs_zcode_dht_record_kind kind, const char *namespace_name,
    const uint8_t root[32], uint64_t now_unix,
    struct vcs_zcode_dht_record *out, size_t out_capacity)
{
  if (!store || !namespace_name || !root || (!out && out_capacity))
    return 0;
  size_t count = 0;
  for (size_t i = 0; i < store->count; i++) {
    const struct vcs_zcode_dht_record *record = &store->entries[i].record;
    if (record->kind != kind ||
        strcmp(record->namespace_name, namespace_name) != 0 ||
        memcmp(record_root(record), root, 32) != 0 ||
        now_unix < record->not_before || now_unix >= record->expiry)
      continue;
    if (count < out_capacity)
      out[count] = *record;
    count++;
  }
  return count;
}

size_t vcs_zcode_dht_record_store_scan(
    const struct vcs_zcode_dht_record_store *store,
    enum vcs_zcode_dht_record_kind kind, const char *namespace_name,
    uint64_t now_unix, struct vcs_zcode_dht_record *out,
    size_t out_capacity)
{
  if (!store || !namespace_name || (!out && out_capacity))
    return 0;
  size_t count = 0;
  for (size_t i = 0; i < store->count; i++) {
    const struct vcs_zcode_dht_record *record = &store->entries[i].record;
    if (record->kind != kind ||
        strcmp(record->namespace_name, namespace_name) != 0 ||
        now_unix < record->not_before || now_unix >= record->expiry)
      continue;
    if (count < out_capacity)
      out[count] = *record;
    count++;
  }
  return count;
}

static void digest_entries(const struct vcs_zcode_dht_record_store *store,
                           uint8_t out[32])
{
  struct sha3_256_ctx sha;
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)RECORD_STORE_DIGEST_DOMAIN,
                 sizeof(RECORD_STORE_DIGEST_DOMAIN));
  sha3_256_write(&sha, store->network_genesis, 32);
  uint8_t count_wire[4];
  zcl_write_u32_le(count_wire, (uint32_t)store->count);
  sha3_256_write(&sha, count_wire, sizeof(count_wire));
  for (size_t i = 0; i < store->count; i++)
    sha3_256_write(&sha, store->entries[i].wire,
                   VCS_ZCODE_DHT_RECORD_WIRE_BYTES);
  sha3_256_finalize(&sha, out);
}

void vcs_zcode_dht_record_store_digest(
    const struct vcs_zcode_dht_record_store *store, uint8_t out[32])
{
  if (!out)
    return;
  memset(out, 0, 32);
  if (store)
    digest_entries(store, out);
}

void vcs_zcode_dht_record_store_stream_digest(
    const struct vcs_zcode_dht_record_store *store,
    const struct vcs_zcode_dht_record *record, uint8_t out[32])
{
  if (!out)
    return;
  memset(out, 0, 32);
  if (!store || !record)
    return;
  uint32_t count = 0;
  for (size_t i = 0; i < store->count; i++)
    if (vcs_zcode_dht_record_stream_equal(&store->entries[i].record, record))
      count++;
  struct sha3_256_ctx sha;
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)RECORD_STREAM_DIGEST_DOMAIN,
                 sizeof(RECORD_STREAM_DIGEST_DOMAIN));
  uint8_t count_wire[4];
  zcl_write_u32_le(count_wire, count);
  sha3_256_write(&sha, count_wire, sizeof(count_wire));
  /* entries is globally wire-sorted, so filtering preserves canonical order. */
  for (size_t i = 0; i < store->count; i++)
    if (vcs_zcode_dht_record_stream_equal(&store->entries[i].record, record))
      sha3_256_write(&sha, store->entries[i].wire,
                     VCS_ZCODE_DHT_RECORD_WIRE_BYTES);
  sha3_256_finalize(&sha, out);
}

uint64_t vcs_zcode_dht_record_store_max_sequence(
    const struct vcs_zcode_dht_record_store *store,
    const struct vcs_zcode_dht_record *record)
{
  if (!store || !record)
    return 0;
  uint64_t max_sequence = 0;
  for (size_t i = 0; i < store->count; i++)
    if (vcs_zcode_dht_record_stream_equal(&store->entries[i].record, record) &&
        store->entries[i].record.sequence > max_sequence)
      max_sequence = store->entries[i].record.sequence;
  return max_sequence;
}

static bool store_paths(const char *datadir, char directory[1400],
                        char path[1500], char *error, size_t error_capacity)
{
  if (!datadir || !datadir[0]) {
    (void)store_error(error, error_capacity, VCS_ZCODE_DHT_RECORD_STORE_IO,
                      "record store datadir is missing");
    return false;
  }
  char zcode[1300];
  int n = snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
  if (n <= 0 || (size_t)n >= sizeof(zcode) ||
      !platform_private_directory_ensure(zcode)) {
    (void)store_error(error, error_capacity, VCS_ZCODE_DHT_RECORD_STORE_IO,
                      "cannot create zcode directory");
    return false;
  }
  n = snprintf(directory, 1400, "%s/%s", datadir,
               VCS_ZCODE_DHT_IDENTITY_DIR);
  if (n <= 0 || n >= 1400 ||
      !platform_private_directory_ensure(directory)) {
    (void)store_error(error, error_capacity, VCS_ZCODE_DHT_RECORD_STORE_IO,
                      "cannot create DHT record directory");
    return false;
  }
  n = snprintf(path, 1500, "%s/%s", datadir,
               VCS_ZCODE_DHT_RECORD_STORE_FILE);
  if (n <= 0 || n >= 1500) {
    (void)store_error(error, error_capacity, VCS_ZCODE_DHT_RECORD_STORE_IO,
                      "DHT record path too long");
    return false;
  }
  return true;
}

enum vcs_zcode_dht_record_store_result vcs_zcode_dht_record_store_save(
    const struct vcs_zcode_dht_record_store *store, const char *datadir,
    char *error_out, size_t error_capacity)
{
  if (!store)
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_INVALID,
                       "record store is missing");
  char directory[1400], path[1500];
  if (!store_paths(datadir, directory, path, error_out, error_capacity))
    return VCS_ZCODE_DHT_RECORD_STORE_IO;
  size_t bytes = VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES +
                 store->count * VCS_ZCODE_DHT_RECORD_WIRE_BYTES;
  uint8_t *wire = zcl_calloc(1, bytes, "dht.record_store.save");
  if (!wire)
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_IO,
                       "record store save allocation failed");
  memcpy(wire, record_store_magic, sizeof(record_store_magic));
  zcl_write_u32_le(wire + 8, RECORD_STORE_VERSION);
  zcl_write_u32_le(wire + 12, (uint32_t)store->count);
  memcpy(wire + 16, store->network_genesis, 32);
  digest_entries(store, wire + 48);
  for (size_t i = 0; i < store->count; i++)
    memcpy(wire + VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES +
               i * VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
           store->entries[i].wire, VCS_ZCODE_DHT_RECORD_WIRE_BYTES);

  uint64_t sequence = atomic_fetch_add_explicit(
      &g_record_store_temp_sequence, 1, memory_order_relaxed);
  char temporary[1600];
  int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%llu.%llu", path,
                   (unsigned long long)os_proc_current_pid(),
                   (unsigned long long)sequence);
  if (n <= 0 || (size_t)n >= sizeof(temporary)) {
    free(wire);
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_IO,
                       "record store temp path too long");
  }
  struct platform_private_file staged;
  struct platform_private_file_identity staged_identity;
  platform_private_file_init(&staged);
  bool created = platform_private_file_create(temporary, &staged) &&
                 platform_private_file_identity(&staged, &staged_identity);
  bool ok = created &&
            platform_private_file_write_at(&staged, wire, bytes, 0) &&
            platform_private_file_truncate(&staged, bytes) &&
            platform_private_file_flush(&staged) &&
            platform_private_file_replace(&staged, temporary, path);
  free(wire);
  if (!ok && created)
    (void)platform_private_file_retire_if_identity(
        &staged, temporary, &staged_identity);
  platform_private_file_close(&staged);
  if (!ok) {
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_IO,
                       "record store temp write failed");
  }
  if (!platform_private_parent_flush(directory)) {
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_IO,
                       "record store directory fsync failed");
  }
  if (error_out && error_capacity)
    error_out[0] = '\0';
  return VCS_ZCODE_DHT_RECORD_STORE_OK;
}

enum vcs_zcode_dht_record_store_result vcs_zcode_dht_record_store_load(
    struct vcs_zcode_dht_record_store *store, const char *datadir,
    const struct vcs_zcode_dht_record_verify_context *verify,
    char *error_out, size_t error_capacity)
{
  if (!store || !verify ||
      memcmp(store->network_genesis, verify->network_genesis, 32) != 0)
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_INVALID,
                       "record store load context is invalid");
  char directory[1400], path[1500];
  if (!store_paths(datadir, directory, path, error_out, error_capacity))
    return VCS_ZCODE_DHT_RECORD_STORE_IO;
  struct platform_positioned_file file;
  struct platform_positioned_file_snapshot before, after;
  platform_positioned_file_init(&file);
  if (!platform_positioned_file_open(&file, path)) {
    if (platform_private_path_absent(path))
      return VCS_ZCODE_DHT_RECORD_STORE_OK;
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_IO,
                       "cannot open DHT record store");
  }
  size_t max_bytes = VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES +
                     VCS_ZCODE_DHT_RECORD_STORE_MAX_RECORDS *
                         VCS_ZCODE_DHT_RECORD_WIRE_BYTES;
  if (!platform_positioned_file_is_private(&file) ||
      !platform_positioned_file_snapshot(&file, &before) ||
      before.size < VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES ||
      before.size > max_bytes) {
    platform_positioned_file_close(&file);
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_CORRUPT,
                       "DHT record store size or mode is invalid");
  }
  size_t bytes = (size_t)before.size;
  uint8_t *wire = zcl_malloc(bytes, "dht.record_store.load");
  if (!wire) {
    platform_positioned_file_close(&file);
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_IO,
                       "record store load allocation failed");
  }
  bool read_ok = platform_positioned_file_read(&file, wire, bytes, 0) ==
                     (int64_t)bytes &&
                 platform_positioned_file_snapshot(&file, &after) &&
                 platform_positioned_file_snapshot_equal(&before, &after);
  platform_positioned_file_close(&file);
  if (!read_ok || memcmp(wire, record_store_magic, 8) != 0 ||
      zcl_read_u32_le(wire + 8) != RECORD_STORE_VERSION ||
      memcmp(wire + 16, store->network_genesis, 32) != 0) {
    free(wire);
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_CORRUPT,
                       "DHT record store header is invalid");
  }
  uint32_t count = zcl_read_u32_le(wire + 12);
  if (count > VCS_ZCODE_DHT_RECORD_STORE_MAX_RECORDS ||
      bytes != VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES +
                   (size_t)count * VCS_ZCODE_DHT_RECORD_WIRE_BYTES) {
    free(wire);
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_CORRUPT,
                       "DHT record store count is invalid");
  }
  uint8_t digest[32];
  struct sha3_256_ctx sha;
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)RECORD_STORE_DIGEST_DOMAIN,
                 sizeof(RECORD_STORE_DIGEST_DOMAIN));
  sha3_256_write(&sha, wire + 16, 32);
  sha3_256_write(&sha, wire + 12, 4);
  sha3_256_write(&sha, wire + VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES,
                 bytes - VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES);
  sha3_256_finalize(&sha, digest);
  if (memcmp(digest, wire + 48, 32) != 0) {
    free(wire);
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_CORRUPT,
                       "DHT record store digest is invalid");
  }
  struct vcs_zcode_dht_record_store *temporary =
      vcs_zcode_dht_record_store_create(store->network_genesis);
  if (!temporary) {
    free(wire);
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_IO,
                       "record store rebuild allocation failed");
  }
  bool valid = true;
  for (uint32_t i = 0; valid && i < count; i++) {
    const uint8_t *record_wire =
        wire + VCS_ZCODE_DHT_RECORD_STORE_HEADER_BYTES +
        (size_t)i * VCS_ZCODE_DHT_RECORD_WIRE_BYTES;
    if (i > 0 && memcmp(record_wire - VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
                        record_wire, VCS_ZCODE_DHT_RECORD_WIRE_BYTES) >= 0) {
      valid = false;
      break;
    }
    bool expired = false;
    struct vcs_zcode_dht_record record;
    if (vcs_zcode_dht_record_parse_persisted(
            record_wire, VCS_ZCODE_DHT_RECORD_WIRE_BYTES, verify, &expired,
            &record) != VCS_ZCODE_DHT_RECORD_OK) {
      valid = false;
      break;
    }
    if (expired)
      continue;
    enum vcs_zcode_dht_record_store_result added =
        vcs_zcode_dht_record_store_put(temporary, &record, verify->now_unix);
    if (added != VCS_ZCODE_DHT_RECORD_STORE_ADDED &&
        added != VCS_ZCODE_DHT_RECORD_STORE_CONFLICT)
      valid = false;
  }
  free(wire);
  if (!valid) {
    vcs_zcode_dht_record_store_free(temporary);
    return store_error(error_out, error_capacity,
                       VCS_ZCODE_DHT_RECORD_STORE_CORRUPT,
                       "DHT record store verification failed");
  }
  free(store->entries);
  store->entries = temporary->entries;
  store->count = temporary->count;
  temporary->entries = NULL;
  vcs_zcode_dht_record_store_free(temporary);
  if (error_out && error_capacity)
    error_out[0] = '\0';
  return VCS_ZCODE_DHT_RECORD_STORE_OK;
}
