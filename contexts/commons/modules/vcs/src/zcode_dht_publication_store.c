/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Key-free crash-safe persistence for record renewal intentions. */

#include "zcode_dht_service_internal.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "platform/file_metadata.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define PUBLICATION_STORE_VERSION 1u
#define PUBLICATION_STORE_FILE "zcode/dht/publications.v1"
#define PUBLICATION_STORE_HEADER_BYTES 44u
#define PUBLICATION_STORE_ENTRY_BYTES \
  (VCS_ZCODE_DHT_RECORD_WIRE_BYTES + 8u)
#define PUBLICATION_STORE_MAX_BYTES                                      \
  (PUBLICATION_STORE_HEADER_BYTES +                                     \
   VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS * PUBLICATION_STORE_ENTRY_BYTES + \
   32u)
#define PUBLICATION_STORE_DOMAIN "zcl.zcode.dht.publications.v1"

static const uint8_t publication_magic[8] = {'Z', 'C', 'D', 'H',
                                              'T', 'P', 0x0d, 0x0a};
static _Atomic uint64_t g_publication_store_serial;

static bool publication_path(const char *datadir, char out[1400])
{
  int written = snprintf(out, 1400, "%s/%s", datadir,
                         PUBLICATION_STORE_FILE);
  return written > 0 && written < 1400;
}

static void publication_checksum(const uint8_t *wire, size_t length,
                                 uint8_t out[32])
{
  struct sha3_256_ctx hash;
  sha3_256_init(&hash);
  sha3_256_write(&hash, (const uint8_t *)PUBLICATION_STORE_DOMAIN,
                 sizeof(PUBLICATION_STORE_DOMAIN));
  sha3_256_write(&hash, wire, length);
  sha3_256_finalize(&hash, out);
}

static uint16_t publication_count_used(
    const struct service_publication *publications,
    const struct vcs_zcode_dht_record **first_out)
{
  uint16_t count = 0;
  const struct vcs_zcode_dht_record *first = NULL;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
    if (publications[i].used) {
      count++;
      if (!first)
        first = &publications[i].record;
    }
  *first_out = first;
  return count;
}

static bool publication_wire_encode_entries(
    const struct service_publication *publications, uint8_t *wire,
    size_t *offset_io, char *error_out, size_t error_capacity)
{
  size_t offset = *offset_io;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++) {
    if (!publications[i].used)
      continue;
    if (vcs_zcode_dht_record_encode(&publications[i].record, wire + offset) !=
            VCS_ZCODE_DHT_RECORD_OK ||
        !publications[i].lifetime_s) {
      if (error_out && error_capacity)
        (void)snprintf(error_out, error_capacity,
                       "publication intent encode failed");
      return false;
    }
    offset += VCS_ZCODE_DHT_RECORD_WIRE_BYTES;
    zcl_write_u64_le(wire + offset, publications[i].lifetime_s);
    offset += 8;
  }
  *offset_io = offset;
  return true;
}

static bool publication_stage_create(const char *resolved, char *temporary,
                                     size_t temporary_capacity,
                                     struct platform_private_file *staged)
{
  bool created = false;
  for (unsigned int attempt = 0; attempt < 64 && !created; attempt++) {
    uint64_t serial = atomic_fetch_add_explicit(
                          &g_publication_store_serial, 1,
                          memory_order_relaxed) +
                      1;
    int written = snprintf(temporary, temporary_capacity, "%s.tmp.%llu.%llu",
                           resolved,
                           (unsigned long long)os_proc_current_pid(),
                           (unsigned long long)serial);
    if (written <= 0 || (size_t)written >= temporary_capacity)
      break;
    created = platform_private_file_create(temporary, staged);
    if (!created && errno != EEXIST)
      break;
  }
  return created;
}

static bool publication_commit_staged(
    struct platform_private_file *staged, bool created, const char *temporary,
    const char *resolved, const char *parent, const uint8_t *wire,
    size_t length, char *error_out, size_t error_capacity)
{
  bool ok = created &&
            platform_private_file_write_at(staged, wire, length, 0) &&
            platform_private_file_truncate(staged, length) &&
            platform_private_file_flush(staged) &&
            platform_private_file_replace(staged, temporary, resolved);
  platform_private_file_close(staged);
  if (!ok || !platform_private_parent_flush(parent)) {
    if (created)
      (void)platform_private_file_unlink_missing_ok(temporary);
    if (error_out && error_capacity)
      (void)snprintf(error_out, error_capacity,
                     ok ? "publication intent directory flush failed"
                        : "publication intent atomic write failed");
    return false;
  }
  return true;
}

bool vcs_zcode_dht_publications_save(
    const char *datadir, const struct service_publication *publications,
    char *error_out, size_t error_capacity)
{
  if (!datadir || !publications)
    return false;
  uint8_t wire[PUBLICATION_STORE_MAX_BYTES];
  memset(wire, 0, sizeof(wire));
  memcpy(wire, publication_magic, sizeof(publication_magic));
  zcl_write_u16_le(wire + 8, PUBLICATION_STORE_VERSION);
  const struct vcs_zcode_dht_record *first = NULL;
  uint16_t count = publication_count_used(publications, &first);
  zcl_write_u16_le(wire + 10, count);
  if (first)
    memcpy(wire + 12, first->network_genesis, 32);
  size_t offset = PUBLICATION_STORE_HEADER_BYTES;
  if (!publication_wire_encode_entries(publications, wire, &offset, error_out,
                                       error_capacity))
    return false;
  uint8_t digest[32];
  publication_checksum(wire, offset, digest);
  memcpy(wire + offset, digest, sizeof(digest));
  offset += sizeof(digest);
  char path[1400], resolved[1400], temporary[1460], parent[1400];
  if (!publication_path(datadir, path))
    return false;
  if (!platform_private_path_resolve(path, resolved, sizeof(resolved), parent,
                                     sizeof(parent))) {
    if (error_out && error_capacity)
      (void)snprintf(error_out, error_capacity,
                     "publication intent atomic write failed");
    return false;
  }
  struct platform_private_file staged;
  platform_private_file_init(&staged);
  bool created = publication_stage_create(resolved, temporary,
                                          sizeof(temporary), &staged);
  return publication_commit_staged(&staged, created, temporary, resolved,
                                   parent, wire, offset, error_out,
                                   error_capacity);
}

static bool publication_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
  return a->size == b->size && a->volume == b->volume &&
         a->file_low == b->file_low && a->file_high == b->file_high &&
         a->modified_seconds == b->modified_seconds &&
         a->modified_nanoseconds == b->modified_nanoseconds &&
         a->changed_seconds == b->changed_seconds &&
         a->changed_nanoseconds == b->changed_nanoseconds;
}

static uint64_t publication_lifetime_max(
    enum vcs_zcode_dht_record_kind kind)
{
  if (kind == VCS_ZCODE_DHT_RECORD_PROVIDER)
    return VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS;
  if (kind == VCS_ZCODE_DHT_RECORD_POINTER)
    return VCS_ZCODE_DHT_POINTER_MAX_SECONDS;
  return kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK
             ? VCS_ZCODE_DHT_STORAGE_ACK_MAX_SECONDS
         : kind == VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK
             ? VCS_ZCODE_DHT_SOURCE_REPRODUCTION_ACK_MAX_SECONDS : 0;
}

static bool publication_read_wire(struct vcs_zcode_dht_service *service,
                                  const char *path, uint8_t *wire,
                                  size_t *length_out, bool *present_out)
{
  struct platform_file_metadata metadata;
  enum platform_file_metadata_result probe =
      platform_file_metadata_read(path, &metadata);
  if (probe == PLATFORM_FILE_METADATA_MISSING) {
    *present_out = false;
    return true;
  }
  *present_out = true;
  struct platform_positioned_file file;
  struct platform_positioned_file_snapshot before, after;
  platform_positioned_file_init(&file);
  if (probe != PLATFORM_FILE_METADATA_OK ||
      !platform_positioned_file_open(&file, path) ||
      !platform_positioned_file_snapshot(&file, &before) ||
      !platform_positioned_file_is_private(&file) ||
      before.size < PUBLICATION_STORE_HEADER_BYTES + 32u ||
      before.size > PUBLICATION_STORE_MAX_BYTES) {
    platform_positioned_file_close(&file);
    vcs_zcode_dht_service_set_error(service,
                                    "publication intent size invalid");
    return false;
  }
  *length_out = (size_t)before.size;
  int64_t got = platform_positioned_file_read(&file, wire, *length_out, 0);
  bool read_ok = got == (int64_t)*length_out &&
                 platform_positioned_file_snapshot(&file, &after) &&
                 publication_snapshot_equal(&before, &after);
  platform_positioned_file_close(&file);
  if (!read_ok) {
    vcs_zcode_dht_service_set_error(service,
                                    "publication intent header invalid");
    return false;
  }
  return true;
}

static bool publication_wire_header_valid(
    struct vcs_zcode_dht_service *service, const uint8_t *wire, size_t length,
    uint16_t *count_out)
{
  if (memcmp(wire, publication_magic, sizeof(publication_magic)) != 0 ||
      zcl_read_u16_le(wire + 8) != PUBLICATION_STORE_VERSION) {
    vcs_zcode_dht_service_set_error(service,
                                    "publication intent header invalid");
    return false;
  }
  uint16_t count = zcl_read_u16_le(wire + 10);
  size_t expected = PUBLICATION_STORE_HEADER_BYTES +
                    (size_t)count * PUBLICATION_STORE_ENTRY_BYTES + 32u;
  uint8_t digest[32];
  publication_checksum(wire, length - 32u, digest);
  if (count > VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS || length != expected ||
      (count && memcmp(wire + 12, service->genesis, 32) != 0) ||
      memcmp(digest, wire + length - 32u, 32) != 0) {
    vcs_zcode_dht_service_set_error(service,
                                    "publication intent checksum invalid");
    return false;
  }
  *count_out = count;
  return true;
}

static bool publication_entry_load(
    struct vcs_zcode_dht_service *service, const uint8_t *wire,
    size_t *offset_io,
    const struct vcs_zcode_dht_record_verify_context *verify,
    struct service_publication *entry)
{
  bool expired = false;
  memset(entry, 0, sizeof(*entry));
  enum vcs_zcode_dht_record_error parsed =
      vcs_zcode_dht_record_parse_persisted(
          wire + *offset_io, VCS_ZCODE_DHT_RECORD_WIRE_BYTES, verify,
          &expired, &entry->record);
  (void)expired;
  *offset_io += VCS_ZCODE_DHT_RECORD_WIRE_BYTES;
  uint64_t lifetime = zcl_read_u64_le(wire + *offset_io);
  *offset_io += 8;
  /* One stream's record going bad between save and reboot — a delegation
   * that expired, a datadir inherited by a new identity — must not cost
   * the OTHER streams their renewal. The checksum already vouched for the
   * file as a whole, so a per-entry failure indicts the record, not the
   * file: skip the entry and keep the rest. */
  if (parsed != VCS_ZCODE_DHT_RECORD_OK || !lifetime ||
      lifetime > publication_lifetime_max(entry->record.kind) ||
      memcmp(entry->record.provider_node_id, service->self_id, 32) != 0)
    return false;
  entry->used = true;
  if (entry->record.kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK) {
    service->next_possession_proof_epoch++;
    if (!service->next_possession_proof_epoch)
      service->next_possession_proof_epoch++;
    entry->possession_proof_epoch =
        service->next_possession_proof_epoch;
  }
  entry->lifetime_s = lifetime;
  entry->backoff_s = 30;
  entry->phase = SERVICE_PUBLICATION_NEEDS_LOOKUP;
  return true;
}

bool vcs_zcode_dht_publications_load(struct vcs_zcode_dht_service *service,
                                     uint64_t now_unix)
{
  if (!service)
    return false;
  char path[1400];
  if (!publication_path(service->datadir, path))
    return false;
  uint8_t wire[PUBLICATION_STORE_MAX_BYTES];
  size_t length = 0;
  bool present = false;
  if (!publication_read_wire(service, path, wire, &length, &present))
    return false;
  if (!present)
    return true;
  uint16_t count = 0;
  if (!publication_wire_header_valid(service, wire, length, &count))
    return false;
  struct vcs_zcode_dht_record_verify_context verify = {
      .now_unix = now_unix,
      .authority_verify = service->authority_verify,
      .authority_ctx = service->authority_ctx,
  };
  memcpy(verify.network_genesis, service->genesis, 32);
  struct service_publication loaded[VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS];
  memset(loaded, 0, sizeof(loaded));
  size_t restored = 0, skipped = 0;
  size_t offset = PUBLICATION_STORE_HEADER_BYTES;
  for (uint16_t i = 0; i < count; i++) {
    struct service_publication entry;
    if (publication_entry_load(service, wire, &offset, &verify, &entry))
      loaded[restored++] = entry;
    else
      skipped++;
  }
  if (skipped)
    vcs_zcode_dht_service_set_error(
        service, "publication intents restored with entries skipped");
  memcpy(service->publications, loaded, sizeof(loaded));
  return true;
}
