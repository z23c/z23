/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `z23 app` front door: one plain command per step of the app journey,
 * with no JSON, no plan ids and no pasted hex.
 *
 *   z23 app list                    catalog apps, installed manifests, and
 *                                   your copies (name and status)
 *   z23 app open skycombat          a catalog app (app.open, unchanged)
 *   z23 app copy skycombat          app.copy: adopt the datadir's release of
 *                                   the app, seeding one first through the
 *                                   app.seed leaf when there is none
 *   z23 app save skycombat-1        app.save: save the copy's edits
 *   z23 app build skycombat-1       app.build: build the saved copy
 *   z23 app open skycombat-1        app.run.copy: run that exact image
 *   z23 app share skycombat-1       app.share: save if needed, sign with the
 *                                   owner's key, write skycombat-1.z23share
 *   z23 app open x.z23share         app.receive: verify, keep, build, open
 *
 * Each step is a registry leaf with a plan half and a confirm half. The CLI
 * runs the plan, asks one y/N (command/cli_confirm.h), and only then runs
 * the confirm with the plan's own plan_id and, for an open, the plan's own
 * image_sha3. With no terminal and no --yes it prints the plan and the
 * command that would go ahead, and changes nothing.
 *
 * Authority stays with the leaves: copy, share and receive run owner leaves
 * (adopt, seed, bundle sign, bundle receive) as inner calls, which skip MCP
 * policy, so they are AUTH_OWNER themselves and MCP refuses them. save and
 * the copy open are AUTH_OPERATOR plan-first leaves an agent may also run.
 * The y/N is a convenience for the person at the terminal, never the
 * boundary. Only the argv front door routes `app open NAME` to a copy or a
 * share file; the public app.open leaf never does. */

#ifndef ZCL_TOOLS_NATIVE_APP_FRONT_DOOR_H
#define ZCL_TOOLS_NATIVE_APP_FRONT_DOOR_H

#include "command/cli_confirm.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct json_value;
struct zcl_command_spec;

/* "xxxx-xxxx-xxxx-xxxx" plus NUL. */
#define ZCL_APP_SHORT_FINGERPRINT_LEN 20u

struct zcl_app_front_door {
    const char *verb;    /* copy, save, build, open, share or receive */
    const char *target;  /* an app, a copy name, or a .z23share file */
    const char *datadir; /* the operator datadir */
    struct zcl_cli_confirm confirm;
    FILE *out;           /* human lines; NULL is stdout */
};

/* Run one verb: plan, ask, confirm. Returns the process exit code: 0 when
 * the verb finished or only planned, else the refusing leaf's code. `open`
 * routes a .z23share file to receive and a copy under <datadir>/copies to
 * the copy open; any other name is the catalog app.open. */
int zcl_app_front_door_run(const struct zcl_app_front_door *door);

/* The argv hook: true (with *rc set) when `words` after `consumed` are the
 * plain front-door form of one of the verbs above (exactly one target and
 * at most --yes, -y), which it then runs. False leaves the ordinary leaf
 * dispatch untouched, so --input, plan_id and confirm keep working. */
bool zcl_app_front_door_try(const struct zcl_command_spec *spec,
                            const char *const *words, size_t count,
                            size_t consumed, const char *datadir, int *rc);

/* The short publisher fingerprint people compare by voice or chat: the
 * first 8 bytes of SHA3-256("zcl.app_fingerprint.v1" 0x00 || the 33-byte
 * key) as four dash-separated groups of four hex. False for a key that is
 * not 66 hex characters. */
bool zcl_app_short_fingerprint(const char *pubkey_hex,
                               char out[ZCL_APP_SHORT_FINGERPRINT_LEN]);

/* "k" and 16 hex of the same digest plus NUL. */
#define ZCL_APP_NAMESPACE_LEN 18u

/* The publisher namespace a key owns for app.share: "k" followed by the
 * first 8 bytes of the short fingerprint's digest in lowercase hex. It
 * always passes the release name-half grammar ([a-z0-9-], 1..63). */
bool zcl_app_publisher_namespace(const uint8_t key[33],
                                 char out[ZCL_APP_NAMESPACE_LEN]);

/* app.list's `copies` array: each adopted copy's name and status (read with
 * the zcode.copies reader), then every other directory under
 * <datadir>/copies by name only (received copies). At most 16 rows. */
void zcl_app_list_copies(const char *datadir, struct json_value *data);

#endif /* ZCL_TOOLS_NATIVE_APP_FRONT_DOOR_H */
