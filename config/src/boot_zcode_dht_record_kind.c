/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Record-kind enum <-> wire name codec for DHT record handlers. */

#include "config/boot_zcode_dht_record_kind.h"

#include <string.h>

enum vcs_zcode_dht_record_kind boot_zcode_dht_record_kind_from_name(
    const char *name) {
  if (name && strcmp(name, "provider") == 0)
    return VCS_ZCODE_DHT_RECORD_PROVIDER;
  if (name && strcmp(name, "pointer") == 0)
    return VCS_ZCODE_DHT_RECORD_POINTER;
  if (name && strcmp(name, "storage_ack") == 0)
    return VCS_ZCODE_DHT_RECORD_STORAGE_ACK;
  if (name && strcmp(name, "source_reproduction_ack") == 0)
    return VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK;
  return 0;
}

const char *boot_zcode_dht_record_kind_name(
    enum vcs_zcode_dht_record_kind kind) {
  if (kind == VCS_ZCODE_DHT_RECORD_PROVIDER)
    return "provider";
  if (kind == VCS_ZCODE_DHT_RECORD_POINTER)
    return "pointer";
  if (kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK)
    return "storage_ack";
  return kind == VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK
      ? "source_reproduction_ack" : "unknown";
}
