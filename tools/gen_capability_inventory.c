/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Generate the complete machine-readable C23 capability inventory.
 *
 * The
 * output is JSON Lines so every capability, duplicate candidate, and untested
 * header invariant remains independently searchable without loading one giant
 * document.  No finding or count is embedded here; all rows come from
 * codeindex_inventory_analyze().
 *
 * Usage: gen_capability_inventory <output.jsonl> [source-root]
 */

#define _POSIX_C_SOURCE 200809L
#include "codeindex/codeindex_inventory.h"
#include "codeindex/codeindex_inventory_render.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(_WIN32)
#include <io.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static int sync_output(FILE *out)
{
#if defined(_WIN32)
    return _commit(_fileno(out));
#else
    return fsync(fileno(out));
#endif
}

static int publish_output(const char *temporary, const char *destination)
{
#if defined(_WIN32)
    wchar_t temporary_wide[4096];
    wchar_t destination_wide[4096];
    if (!temporary || !destination ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, temporary, -1,
                            temporary_wide, 4096) <= 0 ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, destination, -1,
                            destination_wide, 4096) <= 0 ||
        !MoveFileExW(temporary_wide, destination_wide,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        errno = EIO;
        return -1;
    }
    return 0;
#else
    return rename(temporary, destination);
#endif
}

static bool usage_args_ok(int argc)
{
    return argc >= 2 && argc <= 3;
}

static const char *select_source_root(int argc, char **argv)
{
    return argc == 3 ? argv[2] : ".";
}

static bool temp_path_fits(char *temp, size_t size, const char *output)
{
    int n = snprintf(temp, size, "%s.tmp.%ld", output, (long)getpid());
    return n > 0 && (size_t)n < size;
}

static bool write_and_publish_report(const char *output, const char *temp,
                                     const struct ci_inventory_report *report)
{
    FILE *out = fopen(temp, "wb");
    bool ok = out && codeindex_inventory_render(out, report) && fflush(out) == 0 &&
        sync_output(out) == 0;
    if (out && fclose(out) != 0) ok = false;
    if (ok && publish_output(temp, output) != 0) ok = false;
    return ok;
}

int main(int argc, char **argv)
{
    if (!usage_args_ok(argc)) {
        fprintf(stderr, "usage: %s <output.jsonl> [source-root]\n", argv[0]);
        return 2;
    }
    const char *output = argv[1];
    const char *root = select_source_root(argc, argv);
    struct ci_inventory_report *report = codeindex_inventory_analyze(root);
    if (!report) {
        fprintf(stderr, "gen_capability_inventory: analysis failed for %s\n", root);
        return 1;
    }
    char temp[4096];
    if (!temp_path_fits(temp, sizeof(temp), output)) {
        codeindex_inventory_free(report);
        fprintf(stderr, "gen_capability_inventory: output path too long\n");
        return 1;
    }
    bool ok = write_and_publish_report(output, temp, report);
    if (!ok) {
        int saved = errno;
        unlink(temp);
        fprintf(stderr, "gen_capability_inventory: write %s failed: %s\n",
                output, strerror(saved));
    } else {
        fprintf(stderr,
                "gen_capability_inventory: %d capabilities, %d symbols, %d duplicate candidates, %d untested invariants -> %s\n",
                report->capability_count, report->symbol_count,
                report->duplicate_count, report->invariant_count, output);
    }
    codeindex_inventory_free(report);
    return ok ? 0 : 1;
}
