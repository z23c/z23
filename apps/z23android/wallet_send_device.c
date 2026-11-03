/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_send_device.h"
#include "base/cleanse.h"
#include <stdio.h>
#include <string.h>

bool wsd_init(struct wsd *device, void *ctx, bool (*ops)(void *ctx, struct zapp_devkey_ops *out), const char *files)
{
    memset(device, 0, sizeof(*device));
    device->ctx = ctx;
    device->ops = ops;
    device->purpose = ZAPP_DEVKEY_PURPOSE_PAYMENT;
    int n = files ? snprintf(device->blob, sizeof(device->blob), "%s/wallet_key.blob", files) : -1;
    return ops && n > 0 && (size_t)n < sizeof(device->blob);
}

static enum wss_key_status unwrap(void *ctx, uint8_t secret[32])
{
    struct wsd *device = ctx;
    struct zapp_devkey_ops ops;
    memory_cleanse(secret, ZAPP_DEVKEY_SECRET);
    if (!device->ops(device->ctx, &ops)) return WSS_KEY_ERROR;
    enum zapp_devkey_status status = zapp_devkey_unwrap(&ops, device->blob, device->purpose, secret);
    enum wss_key_status key = wss_key_status_of_devkey(zapp_devkey_status_name(status));
    if (key != WSS_KEY_OK) memory_cleanse(secret, ZAPP_DEVKEY_SECRET);
    return key;
}

void wsd_ops(struct wsd *device, struct wss_device_ops *ops)
{
    *ops = (struct wss_device_ops){device, unwrap};
}

void wsd_set_purpose(struct wsd *device, enum zapp_devkey_purpose purpose)
{
    device->purpose = purpose;
}
