/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the `z23 app` front door (see native_app_front_door.h). RED:
 * pinned by test_app_front_door before the verbs exist. */

#include "command/native_app_front_door.h"

int zcl_app_front_door_run(const struct zcl_app_front_door *door)
{
    (void)door;
    return 2;
}

bool zcl_app_front_door_try(const struct zcl_command_spec *spec,
                            const char *const *words, size_t count,
                            size_t consumed, const char *datadir, int *rc)
{
    (void)spec;
    (void)words;
    (void)count;
    (void)consumed;
    (void)datadir;
    (void)rc;
    return false;
}

bool zcl_app_short_fingerprint(const char *pubkey_hex,
                               char out[ZCL_APP_SHORT_FINGERPRINT_LEN])
{
    (void)pubkey_hex;
    out[0] = '\0';
    return false;
}

void zcl_app_list_copies(const char *datadir, struct json_value *data)
{
    (void)datadir;
    (void)data;
}
