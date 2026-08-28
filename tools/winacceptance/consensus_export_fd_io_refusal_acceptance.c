/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows acceptance for the descriptor-backed SQLite VFS shim
 * consensus export uses -- a read-only open serves reads but answers
 * SQLITE_READONLY to write and truncate, a read-write open is refused
 * outright, and the underlying descriptor bytes are proven unchanged. */
#include "consensus_state_snapshot_export_internal.h"

#include "base/safe_alloc.h"

#include <fcntl.h>
#include <io.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char *path = "consensus-export-fd-refusal.tmp";
    const char original[] = "immutable-source";
    int fd = _open(path, _O_CREAT | _O_TRUNC | _O_RDWR | _O_BINARY,
                   _S_IREAD | _S_IWRITE);
    if (fd < 0 || _write(fd, original, sizeof(original)) != sizeof(original))
        return 1;
    sqlite3_file *file = zcl_calloc(1, (size_t)consensus_export_fd_file_size(),
                                   "winacceptance.consensus_export_fd.file");
    if (!file) return 1;
    int flags = SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_READONLY;
    char readback[sizeof(original)] = {0};
    char mutation[sizeof(original)];
    memset(mutation, 'X', sizeof(mutation));
    if (consensus_export_fd_file_open(file, fd, flags, NULL) != SQLITE_OK ||
        file->pMethods->xRead(file, readback, sizeof(readback), 0) != SQLITE_OK ||
        memcmp(readback, original, sizeof(original)) != 0 ||
        file->pMethods->xWrite(file, mutation, sizeof(mutation), 0) !=
            SQLITE_READONLY ||
        file->pMethods->xTruncate(file, 0) != SQLITE_READONLY ||
        file->pMethods->xClose(file) != SQLITE_OK)
        return 1;
    free(file);
    file = zcl_calloc(1, (size_t)consensus_export_fd_file_size(),
                      "winacceptance.consensus_export_fd.file");
    if (!file || consensus_export_fd_file_open(
            file, fd, SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_READWRITE, NULL) !=
            SQLITE_READONLY)
        return 1;
    free(file);
    _lseeki64(fd, 0, SEEK_SET);
    memset(readback, 0, sizeof(readback));
    if (_read(fd, readback, sizeof(readback)) != sizeof(readback) ||
        memcmp(readback, original, sizeof(original)) != 0)
        return 1;
    _close(fd);
    remove(path);
    puts("consensus_export_fd_io_refusal_acceptance: PASS");
    return 0;
}
