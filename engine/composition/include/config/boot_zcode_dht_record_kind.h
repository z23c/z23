/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Record-kind enum <-> wire name codec for DHT record handlers. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_RECORD_KIND_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_RECORD_KIND_H

#include "vcs/zcode_dht_service.h"

/* Wire name -> kind; 0 when name is NULL or not a known record kind. */
enum vcs_zcode_dht_record_kind boot_zcode_dht_record_kind_from_name(
    const char *name);

/* Kind -> wire name; "unknown" for an unrecognized kind. */
const char *boot_zcode_dht_record_kind_name(
    enum vcs_zcode_dht_record_kind kind);

#endif /* ZCL_CONFIG_BOOT_ZCODE_DHT_RECORD_KIND_H */
