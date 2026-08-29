/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_UTIL_H
#define BITCOIN_UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_ARGS   512
#define MAX_ARG_LEN 1024

struct arg_entry {
    char key[MAX_ARG_LEN];
    char value[MAX_ARG_LEN];
};

extern struct arg_entry g_args[MAX_ARGS];
extern int g_nargs;

/* The node's own config file, read from <datadir>. One `key=value` (or bare
 * `key`, meaning true) per line, `#` comments, an optional leading `-` on the
 * key. It exists so a setting can be persisted for the NEXT boot without
 * editing a service unit — `z23 join` writes -packagehost/-buildworker here. */
#define ZCL_NODE_CONFIG_FILENAME "z23.conf"

/* Parse argv[1..] into the g_args table. Accepts -key, -key=value, and
 * --key (normalized to -key); stops at the first non '-' token. A leading
 * -nofoo synthesizes -foo=0 unless -foo was given. Replaces any prior
 * parse and clears the datadir cache. */
void ParseParameters(int argc, const char *const argv[]);

/* Value stored for `arg` (a pointer into g_args, valid until the next
 * ParseParameters), or `default_val` if `arg` was not supplied. */
const char *GetArg(const char *arg, const char *default_val);

/* `arg` parsed as a base-10 integer, or `default_val` if absent. NOTE:
 * an unparseable value yields 0 (strtoll with no error check), not the
 * default. */
int64_t GetArgInt(const char *arg, int64_t default_val);

/* Boolean for `arg`: present-but-empty (-arg) is true; otherwise true iff
 * the value parses non-zero. `default_val` if `arg` is absent. */
bool GetBoolArg(const char *arg, bool default_val);


/* Merge settings from the config file at `path` into the argument table.
 * The COMMAND LINE WINS: a key ParseParameters already set is left alone, so
 * this only fills in what argv did not mention. `-datadir` and `-conf` inside
 * the file are ignored (the file's path comes FROM the datadir). Returns the
 * number of settings applied, or -1 if the file could not be opened — a
 * missing file is the normal case and changes nothing. Call it AFTER
 * ParseParameters, which resets the table. */
int ReadConfigFile(const char *path);

/* Write <datadir>/z23.conf into `out`. `datadir` wins when non-empty; NULL or
 * "" falls back to the -datadir argument, then the platform default. Creates
 * no directory and does not touch the datadir cache — resolving a config-file
 * path must never be the thing that mints an operator's data directory. */
void GetConfigFilePath(const char *datadir, char *out, size_t out_size);

/* -datadir=DIR (or --datadir=DIR) from ANYWHERE in argv, into `out`. Needed
 * because ParseParameters stops at the first non-'-' token, so a CLI
 * invocation such as `z23 zcode work toolchain -datadir=DIR` leaves the
 * argument table empty. Returns false (and empties `out`) when absent. */
bool ArgvDataDir(int argc, const char *const argv[], char *out,
                 size_t out_size);

/* True if a log line in `category` should be emitted. NULL category
 * (uncategorized) is always true; a named category requires -debug,
 * -debug=1, or -debug=<category>. */
bool LogAcceptCategory(const char *category);

/* Write `str` to the log sink (stderr); returns the byte count written. */
int LogPrintStr(const char *str);

/* Write the platform default data directory path into `out` (e.g.
 * ~/.zclassic-c23 on Linux), truncated to `out_size`. */
void GetDefaultDataDir(char *out, size_t out_size);

/* Resolve the active data directory into `out` (truncated to `out_size`):
 * the -datadir arg if set, else the platform default; with the network
 * subdirectory appended when `fNetSpecific`. Creates the directory and
 * caches the result. */
void GetDataDir(bool fNetSpecific, char *out, size_t out_size);

/* Invalidate the cached data-directory paths so the next GetDataDir
 * re-resolves them. */
void ClearDataDirCache(void);

/* Pin the data directory to `datadir` (overriding args/default), creating
 * it and its network subdir; empty/NULL only clears the cache. */
bool SetDataDir(const char *datadir);



/* Number of online logical CPUs (>= 1; returns 1 if the count is
 * unavailable on this platform). */
int GetNumCores(void);

#define LogPrintf(...) do { \
    if (LogAcceptCategory(NULL)) { \
        char _logbuf[4096]; \
        snprintf(_logbuf, sizeof(_logbuf), __VA_ARGS__); \
        LogPrintStr(_logbuf); \
    } \
} while(0)

#define LogPrint(category, ...) do { \
    if (LogAcceptCategory(category)) { \
        char _logbuf[4096]; \
        snprintf(_logbuf, sizeof(_logbuf), __VA_ARGS__); \
        LogPrintStr(_logbuf); \
    } \
} while(0)

#endif
