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
  uint16_t count = 0;
  const struct vcs_zcode_dht_record *first = NULL;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
    if (publications[i].used) {
      count++;
      if (!first)
        first = &publications[i].record;
    }
  zcl_write_u16_le(wire + 10, count);
  if (first)
    memcpy(wire + 12, first->network_genesis, 32);
  size_t offset = PUBLICATION_STORE_HEADER_BYTES;
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
  bool created = false;
  for (unsigned int attempt = 0; attempt < 64 && !created; attempt++) {
    uint64_t serial = atomic_fetch_add_explicit(
                          &g_publication_store_serial, 1,
                          memory_order_relaxed) +
                      1;
    int written = snprintf(temporary, sizeof(temporary), "%s.tmp.%llu.%llu",
                           resolved,
                           (unsigned long long)os_proc_current_pid(),
                           (unsigned long long)serial);
    if (written <= 0 || (size_t)written >= sizeof(temporary))
      break;
    created = platform_private_file_create(temporary, &staged);
    if (!created && errno != EEXIST)
      break;
  }
  bool ok = created &&
            platform_private_file_write_at(&staged, wire, offset, 0) &&
            platform_private_file_truncate(&staged, offset) &&
            platform_private_file_flush(&staged) &&
            platform_private_file_replace(&staged, temporary, resolved);
  platform_private_file_close(&staged);
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

bool vcs_zcode_dht_publications_load(struct vcs_zcode_dht_service *service,
                                     uint64_t now_unix)
{
  if (!service)
    return false;
  char path[1400];
  if (!publication_path(service->datadir, path))
    return false;
  struct platform_file_metadata metadata;
  enum platform_file_metadata_result probe =
      platform_file_metadata_read(path, &metadata);
  if (probe == PLATFORM_FILE_METADATA_MISSING)
    return true;
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
  size_t length = (size_t)before.size;
  uint8_t wire[PUBLICATION_STORE_MAX_BYTES];
  int64_t got = platform_positioned_file_read(&file, wire, length, 0);
  bool read_ok = got == (int64_t)length &&
                 platform_positioned_file_snapshot(&file, &after) &&
                 publication_snapshot_equal(&before, &after);
  platform_positioned_file_close(&file);
  if (!read_ok || memcmp(wire, publication_magic, sizeof(publication_magic)) != 0 ||
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
  struct vcs_zcode_dht_record_verify_context verify = {
      .now_unix = now_unix,
      .chain_verify = service->chain_verify,
      .chain_ctx = service->chain_ctx,
  };
  memcpy(verify.network_genesis, service->genesis, 32);
  struct service_publication loaded[VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS];
  memset(loaded, 0, sizeof(loaded));
  size_t restored = 0, skipped = 0;
  size_t offset = PUBLICATION_STORE_HEADER_BYTES;
  for (uint16_t i = 0; i < count; i++) {
    bool expired = false;
    struct service_publication entry;
    memset(&entry, 0, sizeof(entry));
    enum vcs_zcode_dht_record_error parsed =
        vcs_zcode_dht_record_parse_persisted(
            wire + offset, VCS_ZCODE_DHT_RECORD_WIRE_BYTES, &verify,
            &expired, &entry.record);
    (void)expired;
    offset += VCS_ZCODE_DHT_RECORD_WIRE_BYTES;
    uint64_t lifetime = zcl_read_u64_le(wire + offset);
    offset += 8;
    /* One stream's record going bad between save and reboot — a delegation
     * that expired, a datadir inherited by a new identity — must not cost
     * the OTHER streams their renewal. The checksum already vouched for the
     * file as a whole, so a per-entry failure indicts the record, not the
     * file: skip the entry and keep the rest. */
    if (parsed != VCS_ZCODE_DHT_RECORD_OK || !lifetime ||
        lifetime > publication_lifetime_max(entry.record.kind) ||
        memcmp(entry.record.provider_node_id, service->self_id, 32) != 0) {
      skipped++;
      continue;
    }
    entry.used = true;
    if (entry.record.kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK) {
      service->next_possession_proof_epoch++;
      if (!service->next_possession_proof_epoch)
        service->next_possession_proof_epoch++;
      entry.possession_proof_epoch =
          service->next_possession_proof_epoch;
    }
    entry.lifetime_s = lifetime;
    entry.backoff_s = 30;
    entry.phase = SERVICE_PUBLICATION_NEEDS_LOOKUP;
    loaded[restored++] = entry;
  }
  if (skipped)
    vcs_zcode_dht_service_set_error(
        service, "publication intents restored with entries skipped");
  memcpy(service->publications, loaded, sizeof(loaded));
  return true;
}
