/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Derive one allowlisted libm control recipe without changing package source.
 */

#include "vcs/package_recipe.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc != 3) {
        fputs("usage: skycombat-recipe-libm INPUT_RECIPE OUTPUT_RECIPE\n", stderr);
        return 2;
    }
    FILE *input = fopen(argv[1], "rb");
    if (!input) {
        perror("recipe input");
        return 1;
    }
    uint8_t wire[VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES];
    size_t length = fread(wire, 1, sizeof(wire), input);
    int extra = fgetc(input);
    bool read_ok = !ferror(input) && extra == EOF;
    if (fclose(input) != 0) read_ok = false;
    if (!read_ok) {
        fputs("recipe read failed or exceeded the wire bound\n", stderr);
        return 1;
    }
    struct vcs_package_recipe recipe;
    enum vcs_package_recipe_error error =
        vcs_package_recipe_parse(wire, length, &recipe);
    if (error != VCS_PACKAGE_RECIPE_OK) {
        fprintf(stderr, "recipe parse: %s\n",
                vcs_package_recipe_error_string(error));
        return 1;
    }
    if (!vcs_package_recipe_add_library(
            &recipe, VCS_PACKAGE_RECIPE_LIB_LIBM, &error)) {
        fprintf(stderr, "recipe library: %s\n",
                vcs_package_recipe_error_string(error));
        vcs_package_recipe_free(&recipe);
        return 1;
    }
    uint8_t *encoded = NULL;
    size_t encoded_length = 0;
    error = vcs_package_recipe_serialize(&recipe, &encoded, &encoded_length);
    if (error != VCS_PACKAGE_RECIPE_OK) {
        fprintf(stderr, "recipe serialize: %s\n",
                vcs_package_recipe_error_string(error));
        vcs_package_recipe_free(&recipe);
        return 1;
    }
    uint8_t root[32];
    error = vcs_package_recipe_root(&recipe, root);
    vcs_package_recipe_free(&recipe);
    if (error != VCS_PACKAGE_RECIPE_OK) {
        fprintf(stderr, "recipe root: %s\n",
                vcs_package_recipe_error_string(error));
        free(encoded);
        return 1;
    }
    FILE *output = fopen(argv[2], "wb");
    if (!output) {
        perror("recipe output");
        free(encoded);
        return 1;
    }
    bool write_ok = fwrite(encoded, 1, encoded_length, output) ==
                    encoded_length;
    if (fclose(output) != 0) write_ok = false;
    free(encoded);
    if (!write_ok) {
        fputs("recipe output write failed\n", stderr);
        return 1;
    }
    for (size_t i = 0; i < sizeof(root); i++) printf("%02x", root[i]);
    putchar('\n');
    return 0;
}
