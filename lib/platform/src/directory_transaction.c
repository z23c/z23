/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Implement retained private-directory child transactions. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/directory_transaction.h"
#include "platform/private_directory.h"
#include "base/safe_alloc.h"
#if defined(_WIN32)
#include "private_acl_internal.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool valid_leaf(const char *leaf)
{
    if (!leaf || !leaf[0] || strlen(leaf) > PLATFORM_DIRECTORY_CHILD_LEAF_MAX ||
        !strcmp(leaf, ".") || !strcmp(leaf, "..") || strchr(leaf, '/') ||
        strchr(leaf, '\\') || strchr(leaf, ':'))
        return false;
    size_t n = strlen(leaf);
    if (leaf[n - 1] == '.' || leaf[n - 1] == ' ')
        return false;
#if defined(_WIN32)
    char stem[16]; size_t stem_len = strcspn(leaf, ".");
    if (stem_len >= sizeof(stem)) stem_len = sizeof(stem) - 1;
    for (size_t i = 0; i < stem_len; ++i) {
        unsigned char c = (unsigned char)leaf[i];
        stem[i] = (char)(c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c);
    }
    stem[stem_len] = 0;
    if (!strcmp(stem,"CON") || !strcmp(stem,"PRN") || !strcmp(stem,"AUX") ||
        !strcmp(stem,"NUL") ||
        (stem_len == 4 && (!memcmp(stem,"COM",3) || !memcmp(stem,"LPT",3)) &&
         stem[3] >= '1' && stem[3] <= '9')) return false;
#endif
    return true;
}

static int name_compare(const void *a, const void *b)
{ return strcmp(*(char *const *)a, *(char *const *)b); }

void platform_directory_transaction_init(struct platform_directory_transaction *d)
{ if (d) d->native = UINTPTR_MAX; }
void platform_directory_child_init(struct platform_directory_child *f)
{ if (f) { f->native = UINTPTR_MAX; f->leaf[0] = 0; } }
void platform_directory_lock_init(struct platform_directory_lock *lock)
{ if (lock) lock->native = UINTPTR_MAX; }

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>

#ifndef FILE_OPEN
#define FILE_OPEN 1u
#define FILE_CREATE 2u
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x40u
#define FILE_OPEN_REPARSE_POINT 0x00200000u
#define FILE_SYNCHRONOUS_IO_NONALERT 0x20u
#define FILE_DIRECTORY_FILE 0x1u
#endif

typedef NTSTATUS (NTAPI *nt_create_file_fn)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *nt_set_information_file_fn)(HANDLE, PIO_STATUS_BLOCK,
    PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI *nt_query_directory_file_fn)(
    HANDLE,HANDLE,PVOID,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,
    FILE_INFORMATION_CLASS,BOOLEAN,PUNICODE_STRING,BOOLEAN);

static INIT_ONCE create_once = INIT_ONCE_STATIC_INIT;
static INIT_ONCE set_once = INIT_ONCE_STATIC_INIT;
static INIT_ONCE query_once = INIT_ONCE_STATIC_INIT;
static nt_create_file_fn create_cached;
static nt_set_information_file_fn set_cached;
static nt_query_directory_file_fn query_cached;

static BOOL CALLBACK resolve_nt_symbols(PINIT_ONCE once, PVOID parameter,
                                        PVOID *context)
{
    (void)once; (void)context;
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    FARPROC symbol = module ? GetProcAddress(module, (const char *)parameter)
                            : NULL;
    if (!strcmp((const char *)parameter, "NtCreateFile"))
        memcpy(&create_cached, &symbol, sizeof(create_cached));
    else if (!strcmp((const char *)parameter, "NtSetInformationFile"))
        memcpy(&set_cached, &symbol, sizeof(set_cached));
    else
        memcpy(&query_cached, &symbol, sizeof(query_cached));
    return TRUE;
}

static nt_create_file_fn resolve_nt_create_file(void)
{
    (void)InitOnceExecuteOnce(&create_once, resolve_nt_symbols,
                              (PVOID)"NtCreateFile", NULL);
    return create_cached;
}
static nt_set_information_file_fn resolve_nt_set_information_file(void)
{
    (void)InitOnceExecuteOnce(&set_once, resolve_nt_symbols,
                              (PVOID)"NtSetInformationFile", NULL);
    return set_cached;
}
static nt_query_directory_file_fn resolve_nt_query_directory_file(void)
{ (void)InitOnceExecuteOnce(&query_once,resolve_nt_symbols,(PVOID)"NtQueryDirectoryFile",NULL);return query_cached; }

static HANDLE dh(const struct platform_directory_transaction *d)
{ return d ? (HANDLE)d->native : INVALID_HANDLE_VALUE; }
static HANDLE fh(const struct platform_directory_child *f)
{ return f ? (HANDLE)f->native : INVALID_HANDLE_VALUE; }
static _Thread_local enum platform_directory_result child_last_result;
static _Thread_local bool child_last_created;

static enum platform_directory_result nt_result(NTSTATUS status)
{
    switch ((ULONG)status) {
    case 0xC0000034u: case 0xC000003Au: return PLATFORM_DIRECTORY_MISSING;
    case 0xC0000035u: return PLATFORM_DIRECTORY_EXISTS;
    case 0xC0000022u: case 0xC0000043u: case 0xC00000BAu:
        return PLATFORM_DIRECTORY_REFUSED;
    default: return PLATFORM_DIRECTORY_IO;
    }
}

static bool wide_leaf(const char *leaf, wchar_t out[260], UNICODE_STRING *name)
{
    if (!valid_leaf(leaf)) return false;
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, leaf, -1,
                                out, 260);
    if (n <= 1) return false;
    name->Buffer = out;
    name->Length = (USHORT)((n - 1) * sizeof(wchar_t));
    name->MaximumLength = (USHORT)(n * sizeof(wchar_t));
    return true;
}

static bool child_open(struct platform_directory_transaction *d,
                       const char *leaf, ULONG disposition,
                       struct platform_directory_child *f)
{
    nt_create_file_fn create_file = resolve_nt_create_file();
    wchar_t wide[260];
    UNICODE_STRING name;
    child_last_result = PLATFORM_DIRECTORY_INVALID;
    child_last_created = false;
    if (!create_file || !d || !f || dh(d) == INVALID_HANDLE_VALUE ||
        !wide_leaf(leaf, wide, &name)) return false;
    OBJECT_ATTRIBUTES attributes;
    struct platform_private_acl acl;
    platform_private_acl_init_empty(&acl);
    if (!platform_private_acl_create(&acl)) return false;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE,
                               dh(d), platform_private_acl_descriptor(&acl));
    IO_STATUS_BLOCK status;
    HANDLE child = INVALID_HANDLE_VALUE;
    NTSTATUS result = create_file(
        &child, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE |
                    FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
        &attributes, &status, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, disposition,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT |
            FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    platform_private_acl_destroy(&acl);
    if (result < 0 || child == INVALID_HANDLE_VALUE) {
        child_last_result = nt_result(result);
        return false;
    }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(child, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                  FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !platform_private_acl_validate_handle(child, false)) {
        CloseHandle(child);
        child_last_result = PLATFORM_DIRECTORY_REFUSED;
        return false;
    }
    f->native = (uintptr_t)child;
    (void)memcpy(f->leaf, leaf, strlen(leaf) + 1u);
    child_last_result = PLATFORM_DIRECTORY_OK;
    child_last_created = status.Information == 2u;
    return true;
}

bool platform_directory_transaction_open(struct platform_directory_transaction *d,
                                         const char *path)
{
    uintptr_t handle = 0;
    if (!d || !platform_private_directory_open_validated(path, &handle))
        return false;
    d->native = handle;
    return true;
}
void platform_directory_transaction_close(struct platform_directory_transaction *d)
{ if (d && d->native != UINTPTR_MAX) { platform_private_directory_close(d->native); d->native = UINTPTR_MAX; } }
bool platform_directory_transaction_flush(struct platform_directory_transaction *d)
{
    if (!d || d->native == UINTPTR_MAX) return false;
    BY_HANDLE_FILE_INFORMATION info = {0};
    /* Win32 exposes no supported directory fsync.  Keep the retained parent
     * as the namespace authority and revalidate that it is still the same
     * real directory after the atomic NT namespace operation.  File content
     * durability is provided by platform_directory_child_flush beforehand. */
    return GetFileInformationByHandle(dh(d), &info) != 0 &&
           (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}
enum platform_directory_result platform_directory_transaction_open_child(
    struct platform_directory_transaction *parent, const char *leaf,
    bool create, struct platform_directory_transaction *child)
{
    nt_create_file_fn create_file = resolve_nt_create_file();
    wchar_t wide[260]; UNICODE_STRING name;
    if (!create_file || !parent || !child || !wide_leaf(leaf, wide, &name))
        return PLATFORM_DIRECTORY_INVALID;
    struct platform_private_acl acl; platform_private_acl_init_empty(&acl);
    if (!platform_private_acl_create(&acl)) return PLATFORM_DIRECTORY_IO;
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE,
        dh(parent), platform_private_acl_descriptor(&acl));
    IO_STATUS_BLOCK status = {0}; HANDLE handle = INVALID_HANDLE_VALUE;
    NTSTATUS result = create_file(&handle,
        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE | READ_CONTROL,
        &attributes, &status, NULL, FILE_ATTRIBUTE_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        create ? 3u : FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT |
            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    platform_private_acl_destroy(&acl);
    if (result < 0 || handle == INVALID_HANDLE_VALUE) return nt_result(result);
    if (!platform_private_acl_validate_handle(handle, true)) {
        CloseHandle(handle); return PLATFORM_DIRECTORY_REFUSED;
    }
    platform_directory_transaction_close(child);
    child->native = (uintptr_t)handle;
    return PLATFORM_DIRECTORY_OK;
}
bool platform_directory_child_open(struct platform_directory_transaction *d,
                                   const char *leaf, struct platform_directory_child *f)
{ return child_open(d, leaf, FILE_OPEN, f); }
bool platform_directory_child_create(struct platform_directory_transaction *d,
                                     const char *leaf, struct platform_directory_child *f)
{ return child_open(d, leaf, FILE_CREATE, f); }
enum platform_directory_result platform_directory_child_open_result(
    struct platform_directory_transaction *d, const char *leaf, bool create,
    bool open_existing, struct platform_directory_child *f, bool *created)
{
    if (created) *created = false;
    ULONG disposition = create && open_existing ? 3u : create ? FILE_CREATE : FILE_OPEN;
    if (!child_open(d, leaf, disposition, f)) return child_last_result;
    if (created) *created = child_last_created;
    return PLATFORM_DIRECTORY_OK;
}
void platform_directory_child_close(struct platform_directory_child *f)
{ if (f && f->native != UINTPTR_MAX) { CloseHandle(fh(f)); platform_directory_child_init(f); } }
bool platform_directory_child_info(struct platform_directory_child *f,
                                   struct platform_directory_child_info *out)
{
    BY_HANDLE_FILE_INFORMATION i;
    FILE_BASIC_INFO basic;
    if (!f || !out || !GetFileInformationByHandle(fh(f), &i) ||
        !GetFileInformationByHandleEx(fh(f), FileBasicInfo, &basic,
                                      sizeof(basic))) return false;
    *out = (struct platform_directory_child_info){
        .size = ((uint64_t)i.nFileSizeHigh << 32) | i.nFileSizeLow,
        .volume = i.dwVolumeSerialNumber, .file_low = i.nFileIndexLow,
        .file_high = i.nFileIndexHigh, .link_count = i.nNumberOfLinks,
        .modified_seconds = basic.LastWriteTime.QuadPart / 10000000,
        .changed_seconds = basic.ChangeTime.QuadPart / 10000000,
        .modified_nanoseconds = (uint32_t)((basic.LastWriteTime.QuadPart % 10000000) * 100),
        .changed_nanoseconds = (uint32_t)((basic.ChangeTime.QuadPart % 10000000) * 100),
        .current_user_only = platform_private_acl_validate_handle(fh(f), false)};
    return true;
}
int64_t platform_directory_child_read(struct platform_directory_child *f,
                                      void *data, size_t size, uint64_t offset)
{
    if (!f || (!data && size) || size > UINT32_MAX) return -1;
    OVERLAPPED ov = {.Offset = (DWORD)offset, .OffsetHigh = (DWORD)(offset >> 32)};
    DWORD got = 0;
    return ReadFile(fh(f), data, (DWORD)size, &got, &ov) ? (int64_t)got : -1;
}
bool platform_directory_child_write(struct platform_directory_child *f,
                                    const void *data, size_t size, uint64_t offset)
{
    if (!f || (!data && size) || size > UINT32_MAX) return false;
    OVERLAPPED ov = {.Offset = (DWORD)offset, .OffsetHigh = (DWORD)(offset >> 32)};
    DWORD wrote = 0;
    return WriteFile(fh(f), data, (DWORD)size, &wrote, &ov) && wrote == size;
}
bool platform_directory_child_truncate(struct platform_directory_child *f,
                                       uint64_t size)
{
    FILE_END_OF_FILE_INFO end = {.EndOfFile = {.QuadPart = (LONGLONG)size}};
    return f && SetFileInformationByHandle(fh(f), FileEndOfFileInfo,
                                           &end, sizeof(end));
}
bool platform_directory_child_flush(struct platform_directory_child *f)
{ return f && FlushFileBuffers(fh(f)) != 0; }

bool platform_directory_child_replace(struct platform_directory_transaction *d,
                                      struct platform_directory_child *staged,
                                      const char *destination, bool no_clobber)
{
    wchar_t wide[260]; UNICODE_STRING ignored;
    nt_set_information_file_fn set_info = resolve_nt_set_information_file();
    if (!set_info || !d || !staged || !wide_leaf(destination, wide, &ignored)) return false;
    size_t name_bytes = wcslen(wide) * sizeof(wchar_t);
    struct rename_ex { ULONG flags; HANDLE root; ULONG length; WCHAR name[1]; };
    size_t bytes = offsetof(struct rename_ex, name) + name_bytes;
    struct rename_ex *info = zcl_calloc(1, bytes, "directory-rename-info");
    if (!info) return false;
    /* POSIX_SEMANTICS is defined only in combination with replacement.
     * A no-clobber rename must pass zero flags; the proven NT class-65 call
     * rejects the otherwise meaningless POSIX-only combination. */
    info->flags = no_clobber ? 0u : (1u | 2u);
    info->root = dh(d); info->length = (ULONG)name_bytes;
    memcpy(info->name, wide, name_bytes);
    IO_STATUS_BLOCK status;
    bool ok = set_info(fh(staged), &status, info, (ULONG)bytes,
                       (FILE_INFORMATION_CLASS)65) >= 0 &&
              platform_directory_transaction_flush(d);
    if (ok)
        (void)snprintf(staged->leaf, sizeof(staged->leaf), "%s", destination);
    free(info);
    return ok;
}
bool platform_directory_child_unlink(struct platform_directory_transaction *d,
                                     const char *leaf, bool missing_ok)
{
    enum platform_directory_result result =
        platform_directory_child_unlink_result(d, leaf);
    return result == PLATFORM_DIRECTORY_OK ||
           (missing_ok && result == PLATFORM_DIRECTORY_MISSING);
}
enum platform_directory_result platform_directory_child_unlink_result(
    struct platform_directory_transaction *d, const char *leaf)
{
    struct platform_directory_child f; platform_directory_child_init(&f);
    if (!platform_directory_child_open(d, leaf, &f)) return child_last_result;
    FILE_DISPOSITION_INFO disposition = {.DeleteFile = TRUE};
    bool ok = SetFileInformationByHandle(fh(&f), FileDispositionInfo,
                                         &disposition, sizeof(disposition)) &&
              platform_directory_transaction_flush(d);
    platform_directory_child_close(&f);
    return ok ? PLATFORM_DIRECTORY_OK : PLATFORM_DIRECTORY_IO;
}

enum platform_directory_result platform_directory_lock_acquire(
    struct platform_directory_transaction *d, const char *leaf, bool create,
    enum platform_directory_lock_mode mode, struct platform_directory_lock *lock)
{
    if (!lock || lock->native != UINTPTR_MAX) return PLATFORM_DIRECTORY_INVALID;
    struct platform_directory_child child; platform_directory_child_init(&child);
    enum platform_directory_result opened = platform_directory_child_open_result(
        d, leaf, create, create, &child, NULL);
    if (opened != PLATFORM_DIRECTORY_OK) return opened;
    OVERLAPPED operation = {0};
    DWORD flags = LOCKFILE_FAIL_IMMEDIATELY |
                  (mode == PLATFORM_DIRECTORY_LOCK_EXCLUSIVE
                       ? LOCKFILE_EXCLUSIVE_LOCK : 0);
    if (!LockFileEx(fh(&child), flags, 0, UINT32_MAX, UINT32_MAX, &operation)) {
        platform_directory_child_close(&child);
        return GetLastError() == ERROR_LOCK_VIOLATION
                   ? PLATFORM_DIRECTORY_REFUSED : PLATFORM_DIRECTORY_IO;
    }
    lock->native = child.native; child.native = UINTPTR_MAX;
    return PLATFORM_DIRECTORY_OK;
}

void platform_directory_lock_release(struct platform_directory_lock *lock)
{
    if (!lock || lock->native == UINTPTR_MAX) return;
    OVERLAPPED operation = {0};
    (void)UnlockFileEx((HANDLE)lock->native, 0, UINT32_MAX, UINT32_MAX,
                       &operation);
    CloseHandle((HANDLE)lock->native);
    platform_directory_lock_init(lock);
}

bool platform_directory_transaction_list_regular(
    struct platform_directory_transaction *d, struct platform_directory_names *out)
{
    nt_query_directory_file_fn query = resolve_nt_query_directory_file();
    if (!query || !d || !out) return false;
    memset(out, 0, sizeof(*out));
    BYTE buffer[16384]; bool restart = true;
    for (;;) {
        IO_STATUS_BLOCK status = {0};
        NTSTATUS result = query(dh(d), NULL, NULL, NULL, &status, buffer,
            sizeof(buffer), FileIdBothDirectoryInformation, FALSE, NULL,
            restart ? TRUE : FALSE);
        restart = false;
        if ((ULONG)result == 0x80000006u) break;
        if (result < 0 || status.Information == 0) {
            platform_directory_names_free(out); return false;
        }
        FILE_ID_BOTH_DIR_INFO *entry = (FILE_ID_BOTH_DIR_INFO *)buffer;
        for (;;) {
            if ((entry->FileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                          FILE_ATTRIBUTE_REPARSE_POINT)) == 0) {
                int chars = (int)(entry->FileNameLength / sizeof(wchar_t));
                int need = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                    entry->FileName, chars, NULL, 0, NULL, NULL);
                char *name = need > 0
                    ? zcl_malloc((size_t)need + 1u, "directory-child-name")
                    : NULL;
                char **items = name ? zcl_realloc(out->items,
                    (out->count + 1u) * sizeof(*items), "directory-child-list")
                    : NULL;
                if (!items || WideCharToMultiByte(CP_UTF8,
                    WC_ERR_INVALID_CHARS, entry->FileName, chars, name, need,
                    NULL, NULL) != need) {
                    free(name); platform_directory_names_free(out); return false;
                }
                name[need] = 0; out->items = items;
                out->items[out->count++] = name;
            }
            if (!entry->NextEntryOffset) break;
            entry = (FILE_ID_BOTH_DIR_INFO *)
                ((BYTE *)entry + entry->NextEntryOffset);
        }
    }
    qsort(out->items, out->count, sizeof(*out->items), name_compare);
    return true;
}

#else
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1u
#endif
#endif
#include <unistd.h>

static int dd(const struct platform_directory_transaction *d) { return (int)d->native; }
static int ff(const struct platform_directory_child *f) { return (int)f->native; }
bool platform_directory_transaction_open(struct platform_directory_transaction *d,
                                         const char *path)
{ uintptr_t h; if (!d || !platform_private_directory_open_validated(path, &h)) return false; d->native = h; return true; }
void platform_directory_transaction_close(struct platform_directory_transaction *d)
{ if (d && d->native != UINTPTR_MAX) { close(dd(d)); d->native = UINTPTR_MAX; } }
bool platform_directory_transaction_flush(struct platform_directory_transaction *d)
{ return d && fsync(dd(d)) == 0; }
enum platform_directory_result platform_directory_transaction_open_child(struct platform_directory_transaction*p,const char*l,bool create,struct platform_directory_transaction*c){if(!p||!c||!valid_leaf(l))return PLATFORM_DIRECTORY_INVALID;if(create&&mkdirat(dd(p),l,0700)!=0&&errno!=EEXIST){if(errno==EACCES||errno==EPERM||errno==ELOOP)return PLATFORM_DIRECTORY_REFUSED;return PLATFORM_DIRECTORY_IO;}int fd=openat(dd(p),l,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(fd<0){if(errno==ENOENT)return PLATFORM_DIRECTORY_MISSING;if(errno==EACCES||errno==EPERM||errno==ELOOP)return PLATFORM_DIRECTORY_REFUSED;return PLATFORM_DIRECTORY_IO;}struct stat s;if(fstat(fd,&s)||!S_ISDIR(s.st_mode)||s.st_uid!=geteuid()||(s.st_mode&077)!=0){close(fd);return PLATFORM_DIRECTORY_REFUSED;}platform_directory_transaction_close(c);c->native=(uintptr_t)fd;return PLATFORM_DIRECTORY_OK;}
static bool child_at(struct platform_directory_transaction *d, const char *leaf,
                     int flags, struct platform_directory_child *f)
{ if (!d || !f || !valid_leaf(leaf) || strlen(leaf) > PLATFORM_DIRECTORY_CHILD_LEAF_MAX) return false; int fd = openat(dd(d), leaf, flags|O_CLOEXEC|O_NOFOLLOW, 0600); if (fd < 0) return false; struct stat st; if (fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||st.st_nlink!=1||(st.st_mode&077)!=0){close(fd);errno=EACCES;return false;} f->native=(uintptr_t)fd; memcpy(f->leaf,leaf,strlen(leaf)+1u); return true; }
bool platform_directory_child_open(struct platform_directory_transaction *d,const char *l,struct platform_directory_child *f){return child_at(d,l,O_RDWR,f);}
bool platform_directory_child_create(struct platform_directory_transaction *d,const char *l,struct platform_directory_child *f){return child_at(d,l,O_RDWR|O_CREAT|O_EXCL,f);}
enum platform_directory_result platform_directory_child_open_result(
    struct platform_directory_transaction *d,const char*l,bool create,
    bool open_existing,struct platform_directory_child*f,bool*created)
{
    if(created)*created=false;
    int flags=O_RDWR|(create?O_CREAT:0)|((create)?O_EXCL:0);
    if(child_at(d,l,flags,f)){if(created)*created=create;return PLATFORM_DIRECTORY_OK;}
    if(create&&open_existing&&errno==EEXIST&&child_at(d,l,O_RDWR,f))
        return PLATFORM_DIRECTORY_OK;
    if(errno==ENOENT||errno==ENOTDIR)return PLATFORM_DIRECTORY_MISSING;
    if(errno==EEXIST)return PLATFORM_DIRECTORY_EXISTS;
    if(errno==EACCES||errno==EPERM||errno==ELOOP)return PLATFORM_DIRECTORY_REFUSED;
    return valid_leaf(l)?PLATFORM_DIRECTORY_IO:PLATFORM_DIRECTORY_INVALID;
}
void platform_directory_child_close(struct platform_directory_child *f){if(f&&f->native!=UINTPTR_MAX){close(ff(f));platform_directory_child_init(f);}}
bool platform_directory_child_info(struct platform_directory_child *f,struct platform_directory_child_info *o){struct stat s;if(!f||!o||fstat(ff(f),&s)||!S_ISREG(s.st_mode)||s.st_size<0)return false;*o=(struct platform_directory_child_info){.size=(uint64_t)s.st_size,.volume=(uint64_t)s.st_dev,.file_low=(uint64_t)s.st_ino,.file_high=0,.link_count=(uint64_t)s.st_nlink,.modified_seconds=(int64_t)s.st_mtime,.changed_seconds=(int64_t)s.st_ctime,.modified_nanoseconds=(uint32_t)s.st_mtim.tv_nsec,.changed_nanoseconds=(uint32_t)s.st_ctim.tv_nsec,.current_user_only=s.st_uid==geteuid()&&(s.st_mode&077)==0};return true;}
int64_t platform_directory_child_read(struct platform_directory_child *f,void*d,size_t s,uint64_t o){ssize_t n;do{n=pread(ff(f),d,s,(off_t)o);}while(n<0&&errno==EINTR);return n;}
bool platform_directory_child_write(struct platform_directory_child *f,const void*d,size_t s,uint64_t o){const unsigned char*b=d;size_t done=0;while(done<s){ssize_t n=pwrite(ff(f),b+done,s-done,(off_t)(o+done));if(n<0&&errno==EINTR)continue;if(n<=0)return false;done+=(size_t)n;}return true;}
bool platform_directory_child_truncate(struct platform_directory_child *f,uint64_t s){return ftruncate(ff(f),(off_t)s)==0;}
bool platform_directory_child_flush(struct platform_directory_child *f){return fsync(ff(f))==0;}
bool platform_directory_child_replace(struct platform_directory_transaction*d,struct platform_directory_child*f,const char*to,bool no){if(!d||!f||!valid_leaf(f->leaf)||!valid_leaf(to))return false;int moved;if(no){
#if defined(__linux__) && defined(SYS_renameat2)
moved=(int)syscall(SYS_renameat2,dd(d),f->leaf,dd(d),to,RENAME_NOREPLACE);
#else
moved=linkat(dd(d),f->leaf,dd(d),to,0);if(moved==0&&unlinkat(dd(d),f->leaf,0)!=0){(void)unlinkat(dd(d),to,0);return false;}
#endif
}else moved=renameat(dd(d),f->leaf,dd(d),to);if(moved!=0)return false;memcpy(f->leaf,to,strlen(to)+1u);return platform_directory_transaction_flush(d);}
enum platform_directory_result platform_directory_child_unlink_result(struct platform_directory_transaction*d,const char*l){if(!d||!valid_leaf(l))return PLATFORM_DIRECTORY_INVALID;if(unlinkat(dd(d),l,0)==0)return platform_directory_transaction_flush(d)?PLATFORM_DIRECTORY_OK:PLATFORM_DIRECTORY_IO;if(errno==ENOENT)return PLATFORM_DIRECTORY_MISSING;if(errno==EACCES||errno==EPERM||errno==EISDIR)return PLATFORM_DIRECTORY_REFUSED;return PLATFORM_DIRECTORY_IO;}
bool platform_directory_child_unlink(struct platform_directory_transaction*d,const char*l,bool missing){enum platform_directory_result r=platform_directory_child_unlink_result(d,l);return r==PLATFORM_DIRECTORY_OK||(missing&&r==PLATFORM_DIRECTORY_MISSING);}
enum platform_directory_result platform_directory_lock_acquire(struct platform_directory_transaction*d,const char*l,bool create,enum platform_directory_lock_mode mode,struct platform_directory_lock*lock){if(!lock||lock->native!=UINTPTR_MAX)return PLATFORM_DIRECTORY_INVALID;struct platform_directory_child f;platform_directory_child_init(&f);enum platform_directory_result r=platform_directory_child_open_result(d,l,create,create,&f,NULL);if(r!=PLATFORM_DIRECTORY_OK)return r;if(flock(ff(&f),(mode==PLATFORM_DIRECTORY_LOCK_EXCLUSIVE?LOCK_EX:LOCK_SH)|LOCK_NB)!=0){platform_directory_child_close(&f);return errno==EWOULDBLOCK||errno==EAGAIN?PLATFORM_DIRECTORY_REFUSED:PLATFORM_DIRECTORY_IO;}lock->native=f.native;f.native=UINTPTR_MAX;return PLATFORM_DIRECTORY_OK;}
void platform_directory_lock_release(struct platform_directory_lock*l){if(!l||l->native==UINTPTR_MAX)return;(void)flock((int)l->native,LOCK_UN);close((int)l->native);platform_directory_lock_init(l);}
bool platform_directory_transaction_list_regular(struct platform_directory_transaction*d,struct platform_directory_names*out){if(!d||!out)return false;memset(out,0,sizeof(*out));int dupfd=dup(dd(d));DIR*dir=dupfd>=0?fdopendir(dupfd):NULL;if(!dir){if(dupfd>=0)close(dupfd);return false;}struct dirent*e;while((e=readdir(dir))){struct stat s;if(!valid_leaf(e->d_name)||fstatat(dd(d),e->d_name,&s,AT_SYMLINK_NOFOLLOW)||!S_ISREG(s.st_mode))continue;char*n=zcl_strdup(e->d_name,"directory-child-name");if(!n){closedir(dir);platform_directory_names_free(out);return false;}char**items=zcl_realloc(out->items,(out->count+1)*sizeof(*items),"directory-child-list");if(!items){free(n);closedir(dir);platform_directory_names_free(out);return false;}out->items=items;out->items[out->count++]=n;}closedir(dir);qsort(out->items,out->count,sizeof(*out->items),name_compare);return true;}
#endif

bool platform_directory_child_read_exact(struct platform_directory_child *f,
                                         void *data, size_t size,
                                         uint64_t offset)
{
    unsigned char *bytes = data;
    size_t done = 0;
    while (done < size) {
        if (UINT64_MAX - offset < done) return false;
        int64_t got = platform_directory_child_read(
            f, bytes + done, size - done, offset + done);
        if (got <= 0) return false;
        done += (size_t)got;
    }
    return true;
}

bool platform_directory_child_write_exact(struct platform_directory_child *f,
                                          const void *data, size_t size,
                                          uint64_t offset)
{
    const unsigned char *bytes = data;
    size_t done = 0;
    while (done < size) {
        size_t chunk = size - done;
        if (chunk > UINT32_MAX) chunk = UINT32_MAX;
        if (UINT64_MAX - offset < done ||
            !platform_directory_child_write(f, bytes + done, chunk,
                                            offset + done)) return false;
        done += chunk;
    }
    return true;
}

void platform_directory_names_free(struct platform_directory_names *names)
{ if (!names) return; for (size_t i=0;i<names->count;i++) free(names->items[i]); free(names->items); memset(names,0,sizeof(*names)); }
