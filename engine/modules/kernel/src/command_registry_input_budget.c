/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Per-key input value bounds, split out of command_registry.c so that file
 * stays under its recorded file-size-ceiling baseline. Behaviour is
 * unchanged: same functions, same constants (now shared via
 * kernel/command_registry.h so this file and command_registry.c's
 * validator cannot drift apart), same logic, different translation unit.
 *
 * WHY THE DEFAULT IS 4096, AND WHAT IT PROTECTS. The default branch of
 * zcl_command_registry_input_validate() (command_registry.c) types every
 * key the chain does not name as a string and refuses one longer than
 * ZCL_COMMAND_INPUT_STR_MAX. That number is not protecting a parser
 * (platform/modules/json bounds nesting depth, not string length), a log
 * line (no dispatch path logs an input value), or the reply frame (replies
 * are built from handler output, never echoed input). It is the "no input
 * key is unbounded" floor: it caps how much a caller can make the process
 * hold and hash for ONE argument, and it keeps a typical document inside
 * the shared command frame. It is a property of the DEFAULT — of not
 * knowing what the key carries — not a property of any key.
 *
 * So it is exactly wrong for a key whose value is a hex-encoded wire object
 * that already has a published maximum. A package manifest is bounded by
 * VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES (1 MiB); hex doubles that to 2 MiB of
 * characters. Capping it at 4096 capped a publishable manifest at ~2 KB of
 * wire — roughly three files — so `zcode package publish` worked only for
 * toy packages. Raising the default instead would hand every other key the
 * same 2 MiB, which is the opposite of a bound.
 *
 * Each entry below is DERIVED from the constant that already governs that
 * key's wire, doubled for hex. This function is the single source of truth
 * for "how long may this key be": the validator calls it (it is not
 * restated inline anywhere) and zcl_command_registry_input_budget_bytes()
 * calls it to size the read frame, so validator and reader cannot drift
 * apart. */

#include "kernel/command_registry.h"

/* Included for the *_MAX_WIRE_BYTES constants only — no contexts/commons/modules/vcs symbol is
 * referenced, so this adds no link edge. The include is what makes the
 * package input bounds below DERIVED rather than restated: change a wire's
 * own limit and the input validator follows it in the same build. */
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"

#include <string.h>

size_t zcl_command_registry_input_str_max(const char *key)
{
    if (!key || !key[0])
        return ZCL_COMMAND_INPUT_STR_MAX;
    /* Hex of a canonical package-release envelope (zcode.package.publish.*). */
    if (strcmp(key, "release_hex") == 0)
        return 2u * (size_t)VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES;
    /* Hex of a content.v2 package manifest — the key that made this whole
     * bound load-bearing: one entry per file, up to VCS_PACKAGE_MAX_FILES. */
    if (strcmp(key, "manifest_hex") == 0)
        return 2u * (size_t)VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES;
    /* Hex of a declarative build recipe (zcode.package.recipe wire). */
    if (strcmp(key, "recipe_hex") == 0)
        return 2u * (size_t)VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES;
    /* Canonical hex of the bounded inline c23_corpus_checkpoint.v1 read.
     * The static verifier derives its wire and shard ceilings by querying
     * this same rule, so the transport can neither truncate an admitted
     * checkpoint nor silently widen the handler. */
    if (strcmp(key, "checkpoint") == 0)
        return ZCL_COMMAND_MAX_INPUT;
    /* Canonical hex of the bounded inline c23_corpus_shard.v1 read. */
    if (strcmp(key, "shard") == 0)
        return ZCL_COMMAND_MAX_INPUT;
    /* transaction_controller.c uses a 2,000,000-byte canonical transaction
     * buffer for create/sign. Hex doubles the wire size. */
    if (strcmp(key, "raw_hex") == 0)
        return 4000000u;
    return ZCL_COMMAND_INPUT_STR_MAX;
}

/* Bytes one JSON member costs at its bound: `"key":<value>,`. Strings add
 * two quotes; the trailing comma is charged to every member (one member
 * overpays by a byte, which is slack, not drift). */
static size_t input_member_budget(const char *key, size_t key_len)
{
    size_t value_max;
    if ((key_len == 5 && memcmp(key, "files", 5) == 0) ||
        (key_len == 9 && memcmp(key, "requested", 9) == 0))
        value_max = 2u + ZCL_COMMAND_INPUT_FILES_MAX_ITEMS *
                             (ZCL_COMMAND_INPUT_FILES_PATH_MAX + 3u);
    else if ((key_len == 7 && memcmp(key, "effects", 7) == 0) ||
             (key_len == 6 && memcmp(key, "inputs", 6) == 0) ||
             (key_len == 7 && memcmp(key, "outputs", 7) == 0) ||
             (key_len == 7 && memcmp(key, "prevtxs", 7) == 0))
        value_max = ZCL_COMMAND_MAX_INPUT;
    else
        value_max = 2u + zcl_command_registry_input_str_max(key);
    return key_len + 4u + value_max;
}

size_t zcl_command_registry_input_budget_bytes(
    const struct zcl_command_spec *spec)
{
    size_t total = 3; /* '{', '}', NUL */
    const char *csv = spec ? spec->input_keys : NULL;
    char token[128];
    while (csv && *csv) {
        const char *end = strchr(csv, ',');
        size_t len = end ? (size_t)(end - csv) : strlen(csv);
        if (len > 0 && len < sizeof(token)) {
            memcpy(token, csv, len);
            token[len] = 0;
            total += input_member_budget(token, len);
        }
        if (!end)
            break;
        csv = end + 1;
    }
    /* Floor, never ceiling: a leaf whose keys are all small keeps the frame
     * it has always had, so this change can only widen, never tighten. */
    return total < ZCL_COMMAND_MAX_INPUT ? ZCL_COMMAND_MAX_INPUT : total;
}
