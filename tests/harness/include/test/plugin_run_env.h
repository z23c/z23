/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the signed-plugin-store test environment shared by the plugin_run
 * groups: a private home with a plugin store, a publisher key, and a way to
 * publish and install a signed fixture image under chosen capabilities. */
#ifndef ZCL_TEST_PLUGIN_RUN_ENV_H
#define ZCL_TEST_PLUGIN_RUN_ENV_H

#include "plugin/plugin_store.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PRT_HEX (PLUGIN_HEX_SHA3_512 + 1)

struct prt_env {
    char base[PATH_MAX], home[PATH_MAX], root[PATH_MAX], src[PATH_MAX];
    uint8_t pk[32], sk[32];
};

/* The fixture image with its 16-byte behaviour field (after marker) set to mode and
 * its last two characters to tag, so each (mode, tag) pair is a distinct generation.
 * Caller frees. */
unsigned char *prt_image_of(const char *fixture, const char *marker, const char *mode,
                            const char *tag, size_t *len);
bool prt_env_open(struct prt_env *e);
void prt_env_close(struct prt_env *e);
/* Sign and install an image as plugin `name` declaring `caps` (a JSON list body
 * such as "\"clock\",\"chain.read\""); gen receives the generation id. */
bool prt_publish_bytes(struct prt_env *e, const char *name, const unsigned char *img,
                       size_t len, const char *caps, char gen[PRT_HEX]);

#endif
