/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Key-free crash-safe persistence for record renewal intentions. */

#include "zcode_dht_service_internal.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "util/write_all.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
  char path[1400], temporary[1460], directory[1400];
  if (!publication_path(datadir, path))
    return false;
  uint64_t serial = atomic_fetch_add_explicit(
                        &g_publication_store_serial, 1,
                        memory_order_relaxed) +
                    1;
  (void)snprintf(temporary, sizeof(temporary), "%s.tmp.%ld.%llu", path,
                 (long)getpid(), (unsigned long long)serial);
  int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  bool ok = fd >= 0 && zcl_write_all(fd, wire, offset) && fsync(fd) == 0;
  if (fd >= 0 && close(fd) != 0)
    ok = false;
  if (ok)
    ok = rename(temporary, path) == 0;
  if (!ok) {
    (void)unlink(temporary);
    if (error_out && error_capacity)
      (void)snprintf(error_out, error_capacity,
                     "publication intent atomic write failed");
    return false;
  }
  (void)snprintf(directory, sizeof(directory), "%s/zcode/dht", datadir);
  int directory_fd = open(directory,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  ok = directory_fd >= 0 && fsync(directory_fd) == 0;
  if (directory_fd >= 0)
    (void)close(directory_fd);
  if (!ok && error_out && error_capacity)
    (void)snprintf(error_out, error_capacity,
                   "publication intent directory fsync failed");
  return ok;
}

static bool publication_read_exact(int fd, uint8_t *wire, size_t length)
{
  size_t offset = 0;
  while (offset < length) {
    ssize_t got = read(fd, wire + offset, length - offset);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return false;
    offset += (size_t)got;
  }
  return true;
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
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return errno == ENOENT;
  struct stat status;
  if (fstat(fd, &status) != 0 || status.st_size <
          (off_t)(PUBLICATION_STORE_HEADER_BYTES + 32u) ||
      status.st_size > (off_t)PUBLICATION_STORE_MAX_BYTES) {
    (void)close(fd);
    vcs_zcode_dht_service_set_error(service,
                                    "publication intent size invalid");
    return false;
  }
  size_t length = (size_t)status.st_size;
  uint8_t wire[PUBLICATION_STORE_MAX_BYTES];
  bool read_ok = publication_read_exact(fd, wire, length);
  (void)close(fd);
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
