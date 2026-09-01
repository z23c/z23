/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Internal short DHT-service critical-section adapter. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_ACCESS_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_ACCESS_H

#include <stdbool.h>

struct vcs_zcode_dht_service;

typedef void (*boot_zcode_dht_service_apply_fn)(
    struct vcs_zcode_dht_service *service, void *context);

/* Invokes apply only while the current service is protected from retirement.
 * The callback must not perform filesystem or package-store work. */
bool boot_zcode_dht_service_apply(boot_zcode_dht_service_apply_fn apply,
                                  void *context);

#endif /* ZCL_CONFIG_BOOT_ZCODE_DHT_ACCESS_H */
