/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "util/util.h"
#include "chain/chainparamsbase.h"
#include "platform/private_directory.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <io.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <sched.h>
#endif

struct arg_entry g_args[MAX_ARGS];
int g_nargs = 0;

static char cachedDataDir[4096] = "";
static char cachedDataDirNet[4096] = "";

void ClearDataDirCache(void)
{
    cachedDataDir[0] = '\0';
    cachedDataDirNet[0] = '\0';
}

static int find_arg(const char *key)
{
    for (int i = 0; i < g_nargs; i++) {
        if (strcmp(g_args[i].key, key) == 0)
            return i;
    }
    return -1;
}

void ParseParameters(int argc, const char *const argv[])
{
    ClearDataDirCache();
    g_nargs = 0;
    for (int i = 1; i < argc && g_nargs < MAX_ARGS; i++) {
        const char *arg = argv[i];
        const char *eq = strchr(arg, '=');
        char key[MAX_ARG_LEN];
        char value[MAX_ARG_LEN];

        if (eq) {
            size_t klen = (size_t)(eq - arg);
            if (klen >= MAX_ARG_LEN) klen = MAX_ARG_LEN - 1;
            memcpy(key, arg, klen);
            key[klen] = '\0';
            snprintf(value, MAX_ARG_LEN, "%s", eq + 1);
        } else {
            snprintf(key, MAX_ARG_LEN, "%s", arg);
            value[0] = '\0';
        }

        if (key[0] != '-') break;

        /* --foo → -foo */
        const char *k = key;
        if (k[0] == '-' && k[1] == '-')
            k++;

        int idx = find_arg(k);
        if (idx >= 0) {
            snprintf(g_args[idx].value, MAX_ARG_LEN, "%s", value);
        } else {
            snprintf(g_args[g_nargs].key, MAX_ARG_LEN, "%s", k);
            snprintf(g_args[g_nargs].value, MAX_ARG_LEN, "%s", value);
            g_nargs++;
        }
    }

    /* Interpret -nofoo as -foo=0 */
    for (int i = 0; i < g_nargs; i++) {
        if (strncmp(g_args[i].key, "-no", 3) == 0) {
            char positive[MAX_ARG_LEN];
            snprintf(positive, sizeof(positive), "-%s", g_args[i].key + 3);
            if (find_arg(positive) < 0 && g_nargs < MAX_ARGS) {
                bool val = !GetBoolArg(g_args[i].key, false);
                snprintf(g_args[g_nargs].key, MAX_ARG_LEN, "%s", positive);
                snprintf(g_args[g_nargs].value, MAX_ARG_LEN, "%d", val ? 1 : 0);
                g_nargs++;
            }
        }
    }
}


/* ── the node's own config file ────────────────────────────────────────────
 *
 * ParseParameters() reads argv and nothing else, so before this existed a
 * setting could only be delivered by editing the service unit's ExecStart.
 * `z23 join` has to be able to persist -packagehost/-buildworker for the NEXT
 * boot without touching systemd and without ever restarting the node itself,
 * which is what this reader is for.
 *
 * PRECEDENCE: the command line ALWAYS wins. A key already present in g_args
 * (i.e. supplied on argv) is left exactly as parsed; the file only fills keys
 * argv did not mention. That ordering is what keeps a unit's ExecStart the
 * final authority on a running fleet node.
 *
 * `-datadir` and `-conf` are deliberately IGNORED from inside the file: the
 * file's own path is derived from the datadir, so honouring a datadir there
 * would mean the file could relocate the directory it was just read out of.
 */
int ReadConfigFile(const char *path)
{
    if (!path || !path[0])
        return -1;
    FILE *f = fopen(path, "re");
    if (!f)
        return -1;

    int applied = 0;
    char line[MAX_ARG_LEN * 2];
    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        char *hash = strchr(s, '#');
        if (hash)
            *hash = '\0';
        while (*s == ' ' || *s == '\t')
            s++;
        size_t n = strlen(s);
        while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                         s[n - 1] == ' ' || s[n - 1] == '\t'))
            s[--n] = '\0';
        if (n == 0)
            continue;

        /* A leading dash is optional: both `packagehost=1` and
         * `-packagehost=1` name the same flag, so a line copy-pasted out of
         * an ExecStart works unchanged. */
        if (*s == '-')
            s++;
        if (!*s)
            continue;

        char key[MAX_ARG_LEN];
        char value[MAX_ARG_LEN];
        char *eq = strchr(s, '=');
        if (eq) {
            size_t klen = (size_t)(eq - s);
            /* Trim space between the key and the '=' so `packagehost = 1`
             * is not read as a flag literally named "packagehost ". */
            while (klen > 0 && (s[klen - 1] == ' ' || s[klen - 1] == '\t'))
                klen--;
            if (klen == 0 || klen >= MAX_ARG_LEN - 1)
                continue;
            memcpy(key + 1, s, klen);
            key[0] = '-';
            key[klen + 1] = '\0';
            const char *v = eq + 1;
            while (*v == ' ' || *v == '\t')
                v++;
            snprintf(value, sizeof(value), "%s", v);
        } else {
            if (strlen(s) >= MAX_ARG_LEN - 1)
                continue;
            key[0] = '-';
            snprintf(key + 1, sizeof(key) - 1, "%s", s);
            /* Bare `-flag` is TRUE, matching ParseParameters' present-but-
             * empty rule (GetBoolArg reads an empty value as true). */
            value[0] = '\0';
        }

        if (strcmp(key, "-datadir") == 0 || strcmp(key, "-conf") == 0)
            continue;
        if (find_arg(key) >= 0)   /* argv already decided this one */
            continue;
        if (g_nargs >= MAX_ARGS)
            break;
        snprintf(g_args[g_nargs].key, MAX_ARG_LEN, "%s", key);
        snprintf(g_args[g_nargs].value, MAX_ARG_LEN, "%s", value);
        g_nargs++;
        applied++;
    }
    fclose(f);
    return applied;
}

/* <datadir>/z23.conf for the CURRENT argv, without creating anything. The
 * deliberate difference from GetDataDir() is that this never mkdir()s and
 * never populates the datadir cache: resolving a config-file path must not
 * be the thing that mints an operator's data directory (`z23 help` on a
 * fresh box would otherwise leave one behind). */
void GetConfigFilePath(const char *datadir, char *out, size_t out_size)
{
    if (!out || out_size == 0)
        return;
    char dir[4096];
    if (datadir && datadir[0]) {
        snprintf(dir, sizeof(dir), "%s", datadir);
    } else {
        int idx = find_arg("-datadir");
        if (idx >= 0 && g_args[idx].value[0])
            snprintf(dir, sizeof(dir), "%s", g_args[idx].value);
        else
            GetDefaultDataDir(dir, sizeof(dir));
    }
    snprintf(out, out_size, "%s/%s", dir, ZCL_NODE_CONFIG_FILENAME);
}

/* -datadir= / --datadir= from ANYWHERE in argv.
 *
 * The argument TABLE cannot answer this on its own: ParseParameters stops at
 * the first token that does not begin with '-', so for a CLI invocation like
 * `z23 zcode work toolchain -datadir=/tmp/x` it parses nothing at all and
 * find_arg("-datadir") returns the default. Resolving the config file from
 * that table would silently read the WRONG datadir's config — the operator's
 * live node instead of the instance they named. Scanning argv directly is the
 * same "scanned anywhere in argv" rule src/main.c already applies to its other
 * mode selectors. Returns false when no -datadir was given. */
bool ArgvDataDir(int argc, const char *const argv[], char *out, size_t out_size)
{
    if (!out || out_size == 0)
        return false;
    out[0] = '\0';
    if (!argv)
        return false;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!a)
            continue;
        if (a[0] == '-' && a[1] == '-')
            a++;
        if (strncmp(a, "-datadir=", 9) != 0)
            continue;
        if (!a[9])
            continue;
        snprintf(out, out_size, "%s", a + 9);
        return true;
    }
    return false;
}
const char *GetArg(const char *arg, const char *default_val)
{
    int idx = find_arg(arg);
    if (idx >= 0)
        return g_args[idx].value;
    return default_val;
}

int64_t GetArgInt(const char *arg, int64_t default_val)
{
    int idx = find_arg(arg);
    if (idx >= 0)
        return strtoll(g_args[idx].value, NULL, 10);
    return default_val;
}

bool GetBoolArg(const char *arg, bool default_val)
{
    int idx = find_arg(arg);
    if (idx >= 0) {
        if (g_args[idx].value[0] == '\0')
            return true;
        return atoi(g_args[idx].value) != 0;
    }
    return default_val;
}



bool LogAcceptCategory(const char *category)
{
    if (category != NULL) {
        /* Category logging emits only when -debug (optionally
         * -debug=<category>) was passed on the command line. */
        for (int i = 0; i < g_nargs; i++) {
            if (strcmp(g_args[i].key, "-debug") == 0) {
                if (g_args[i].value[0] == '\0' ||
                    strcmp(g_args[i].value, "1") == 0 ||
                    strcmp(g_args[i].value, category) == 0)
                    return true;
            }
        }
        return false;
    }
    return true;
}

int LogPrintStr(const char *str)
{
    fputs(str, stderr);
    return (int)strlen(str);
}

void GetDefaultDataDir(char *out, size_t out_size)
{
#ifdef _WIN32
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path) == S_OK)
        snprintf(out, out_size, "%s\\ZClassic", path);
    else
        snprintf(out, out_size, "ZClassic");
#elif defined(__APPLE__)
    const char *home = getenv("HOME");
    if (home && home[0])
        snprintf(out, out_size, "%s/Library/Application Support/ZClassic", home);
    else
        snprintf(out, out_size, "/ZClassic");
#else
    const char *home = getenv("HOME");
    if (home && home[0])
        snprintf(out, out_size, "%s/.zclassic-c23", home);
    else
        snprintf(out, out_size, "/.zclassic-c23");
#endif
}

static void AppendNetworkDataDir(char *path, size_t path_size)
{
    const struct base_chain_params *bp = BaseParams();
    if (!bp || !bp->strDataDir[0])
        return;

    size_t len = strlen(path);
    if (len + 1 >= path_size)
        return;
#ifdef _WIN32
    snprintf(path + len, path_size - len, "\\%s", bp->strDataDir);
#else
    snprintf(path + len, path_size - len, "/%s", bp->strDataDir);
#endif
}

/* Create the data directory so that only the user running the node can read
 * it. The datadir holds the wallet and the RPC cookie, so a wider ACL hands
 * out spending authority.
 *
 * CreateDirectoryA(path, NULL) did not do this: a NULL security descriptor
 * means the new directory INHERITS the parent's ACL, so
 * `zclassic -datadir=D:\node` gave every principal in D:\'s default
 * `Users: Modify` entry read access to the wallet. The POSIX arm was already
 * mkdir(path, 0700). platform_private_directory_ensure() is the portable
 * primitive that means the same thing on both: POSIX mkdir(path, 0700) then
 * an owner/exact-0700-mode/no-symlink re-check of the result; Windows
 * CreateDirectoryW with an explicit owner+SYSTEM-only descriptor then a
 * re-check of the live handle's actual ACL, owner and reparse state.
 *
 * Existing paths are accepted only when that same private-directory contract
 * holds. Callers receive failure before the path is cached or used. */
static bool EnsurePrivateDataDir(const char *path)
{
    return platform_private_directory_ensure(path);
}

bool SetDataDir(const char *datadir)
{
    ClearDataDirCache();
    if (!datadir || !datadir[0])
        return true;

    char base[sizeof(cachedDataDir)];
    char network[sizeof(cachedDataDirNet)];
    snprintf(base, sizeof(base), "%s", datadir);
    snprintf(network, sizeof(network), "%s", datadir);
    AppendNetworkDataDir(network, sizeof(network));

    if (!EnsurePrivateDataDir(base) || !EnsurePrivateDataDir(network))
        return false;
    snprintf(cachedDataDir, sizeof(cachedDataDir), "%s", base);
    snprintf(cachedDataDirNet, sizeof(cachedDataDirNet), "%s", network);
    return true;
}

void GetDataDir(bool fNetSpecific, char *out, size_t out_size)
{
    char *cached = fNetSpecific ? cachedDataDirNet : cachedDataDir;
    if (cached[0]) {
        snprintf(out, out_size, "%s", cached);
        return;
    }

    int idx = find_arg("-datadir");
    if (idx >= 0 && g_args[idx].value[0]) {
        snprintf(out, out_size, "%s", g_args[idx].value);
    } else {
        GetDefaultDataDir(out, out_size);
    }

    if (fNetSpecific) {
        AppendNetworkDataDir(out, out_size);
    }

    if (!EnsurePrivateDataDir(out)) {
        out[0] = '\0';
        return;
    }

    snprintf(cached, 4096, "%s", out);
}






int GetNumCores(void)
{
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_ONLN)
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#else
    return 1;
#endif
}
