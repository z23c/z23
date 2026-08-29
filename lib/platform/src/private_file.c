/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: exclusive-create, lock, and durable-retire operations on a
 * single private file, portable across POSIX and Windows. */
#include "platform/private_file.h"
#include "base/safe_alloc.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>

static HANDLE pf_handle(const struct platform_private_file *file) {
  return (HANDLE)file->native;
}

static bool pf_wide(const char *utf8, wchar_t out[32768]) {
  if (!utf8 || !utf8[0])
    return false;
  wchar_t plain[32768];
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, plain,
                              32768);
  if (n <= 0)
    return false;
  for (int i = 0; i < n - 1; i++)
    if (plain[i] == L'/')
      plain[i] = L'\\';
  if (wcsncmp(plain, L"\\\\?\\", 4) == 0) {
    wmemcpy(out, plain, (size_t)n);
    return true;
  }
  if (plain[0] == L'\\' && plain[1] == L'\\') {
    if ((size_t)n + 6 >= 32768)
      return false;
    wmemcpy(out, L"\\\\?\\UNC\\", 8);
    wmemcpy(out + 8, plain + 2, (size_t)n - 2);
    return true;
  }
  if (plain[0] && plain[1] == L':' && (plain[2] == L'\\' || plain[2] == L'/')) {
    if ((size_t)n + 4 >= 32768)
      return false;
    wmemcpy(out, L"\\\\?\\", 4);
    wmemcpy(out + 4, plain, (size_t)n);
    return true;
  }
  wmemcpy(out, plain, (size_t)n);
  return true;
}

static bool pf_utf8(const wchar_t *wide, char *out, size_t out_size) {
  if (out_size > INT_MAX)
    return false;
  int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, out,
                              (int)out_size, NULL, NULL);
  return n > 0;
}

static PSECURITY_DESCRIPTOR pf_private_descriptor(void) {
  HANDLE token = NULL;
  DWORD bytes = 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    return NULL;
  (void)GetTokenInformation(token, TokenUser, NULL, 0, &bytes);
  TOKEN_USER *user = bytes
      ? zcl_malloc(bytes, "platform-private-file-token-user") : NULL;
  if (!user || !GetTokenInformation(token, TokenUser, user, bytes, &bytes)) {
    free(user);
    CloseHandle(token);
    return NULL;
  }
  LPWSTR sid = NULL;
  bool sid_ok = ConvertSidToStringSidW(user->User.Sid, &sid) != 0;
  free(user);
  CloseHandle(token);
  if (!sid_ok) return NULL;
  wchar_t rule[512];
  int n = swprintf(rule, sizeof(rule) / sizeof(rule[0]),
                   L"D:P(A;;FA;;;SY)(A;;FA;;;%ls)", sid);
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = NULL;
  if (n <= 0 || (size_t)n >= sizeof(rule) / sizeof(rule[0]) ||
      !ConvertStringSecurityDescriptorToSecurityDescriptorW(
          rule, SDDL_REVISION_1, &descriptor, NULL))
    return NULL;
  return descriptor;
}

void platform_private_file_init(struct platform_private_file *file) {
  if (file) {
    file->native = (uintptr_t)INVALID_HANDLE_VALUE;
    file->locked = false;
  }
}

static bool pf_open(const char *path, DWORD creation, DWORD share,
                    struct platform_private_file *file) {
  wchar_t wide[32768];
  if (!file || !pf_wide(path, wide))
    return false;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  SECURITY_ATTRIBUTES security = {.nLength = sizeof(security)};
  if (creation == CREATE_NEW) {
    descriptor = pf_private_descriptor();
    if (!descriptor) return false;
    security.lpSecurityDescriptor = descriptor;
  }
  HANDLE h = CreateFileW(wide, GENERIC_READ | GENERIC_WRITE | DELETE,
                         share, descriptor ? &security : NULL,
                         creation,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                             FILE_FLAG_OVERLAPPED,
                         NULL);
  if (descriptor)
    LocalFree(descriptor);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  BY_HANDLE_FILE_INFORMATION info = {0};
  if (!GetFileInformationByHandle(h, &info) ||
      (info.dwFileAttributes &
       (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
    CloseHandle(h);
    return false;
  }
  file->native = (uintptr_t)h;
  return true;
}

bool platform_private_file_create(const char *path,
                                  struct platform_private_file *file) {
  return pf_open(path, CREATE_NEW, FILE_SHARE_READ, file);
}

bool platform_private_file_open_locked(const char *path,
                                       struct platform_private_file *file) {
  if (!pf_open(path, OPEN_EXISTING, FILE_SHARE_READ, file))
    return false;
  OVERLAPPED ov = {0};
  if (!LockFileEx(pf_handle(file),
                  LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
                  UINT32_MAX, UINT32_MAX, &ov)) {
    platform_private_file_close(file);
    return false;
  }
  file->locked = true;
  return true;
}

bool platform_private_file_open_locked_create(
    const char *path, struct platform_private_file *file) {
  if (platform_private_file_create(path, file)) {
    OVERLAPPED ov = {0};
    if (LockFileEx(pf_handle(file),
                   LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
                   UINT32_MAX, UINT32_MAX, &ov)) {
      file->locked = true;
      return true;
    }
    platform_private_file_close(file);
    return false;
  }
  return platform_private_file_open_locked(path, file);
}

/* Waiting exclusive acquisition. The nonblocking pair above gets its
 * exclusion from the CreateFileW share mode, so a second opener is refused at
 * open time and never reaches the byte-range lock. A waiting lock lets every
 * access requested by pf_open() be shared and takes exclusion solely from the
 * whole-file LockFileEx range.
 *
 * Use bounded-cadence immediate attempts instead of one pending LockFileEx.
 * Native Windows completes the pending form after an unlock, but Wine 11.11
 * leaves that request pending after the owner closes its handle. The immediate
 * form has the same exclusive-lock semantics on both runtimes and keeps each
 * attempt cancel-free. A waited lock file must never be mixed with the
 * nonblocking pair on the same path: their share modes are incompatible. */
static bool pf_lock_wait(struct platform_private_file *file) {
  for (;;) {
    OVERLAPPED ov = {0};
    if (LockFileEx(pf_handle(file),
                   LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
                   UINT32_MAX, UINT32_MAX, &ov)) {
      file->locked = true;
      return true;
    }
    DWORD error = GetLastError();
    if (error != ERROR_LOCK_VIOLATION) {
      SetLastError(error);
      return false;
    }
    Sleep(10);
  }
}

bool platform_private_file_open_locked_wait(
    const char *path, struct platform_private_file *file) {
  /* pf_open requests DELETE as well as read/write access. Windows requires
   * every requested access class to be shared by every existing handle;
   * omitting FILE_SHARE_DELETE makes a contender fail in CreateFileW before
   * it can wait in LockFileEx. */
  if (!pf_open(path, OPEN_EXISTING,
               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, file))
    return false;
  if (!pf_lock_wait(file)) {
    DWORD error = GetLastError();
    platform_private_file_close(file);
    SetLastError(error);
    return false;
  }
  return true;
}

bool platform_private_file_open_locked_create_wait(
    const char *path, struct platform_private_file *file) {
  if (pf_open(path, CREATE_NEW,
              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, file)) {
    if (pf_lock_wait(file))
      return true;
    DWORD error = GetLastError();
    platform_private_file_close(file);
    SetLastError(error);
    return false;
  }
  return platform_private_file_open_locked_wait(path, file);
}

void platform_private_file_close(struct platform_private_file *file) {
  if (!file || pf_handle(file) == INVALID_HANDLE_VALUE)
    return;
  if (file->locked) {
    OVERLAPPED ov = {0};
    (void)UnlockFileEx(pf_handle(file), 0, UINT32_MAX, UINT32_MAX, &ov);
  }
  CloseHandle(pf_handle(file));
  platform_private_file_init(file);
}

bool platform_private_file_size(struct platform_private_file *file,
                                uint64_t *size) {
  LARGE_INTEGER value;
  if (!file || !size || !GetFileSizeEx(pf_handle(file), &value) ||
      value.QuadPart < 0)
    return false;
  *size = (uint64_t)value.QuadPart;
  return true;
}

bool platform_private_file_truncate(struct platform_private_file *file,
                                    uint64_t size) {
  if (size > INT64_MAX)
    return false;
  LARGE_INTEGER pos = {.QuadPart = (LONGLONG)size};
  return SetFilePointerEx(pf_handle(file), pos, NULL, FILE_BEGIN) &&
         SetEndOfFile(pf_handle(file));
}

static bool pf_io(struct platform_private_file *file, void *data, size_t size,
                  uint64_t offset, bool write) {
  unsigned char *p = data;
  size_t done = 0;
  while (done < size) {
    DWORD part = size - done > UINT32_MAX ? UINT32_MAX : (DWORD)(size - done),
          amount = 0;
    uint64_t at = offset + done;
    if (at < offset || (uint64_t)part > UINT64_MAX - at)
      return false;
    OVERLAPPED ov = {0};
    ov.Offset = (DWORD)at;
    ov.OffsetHigh = (DWORD)(at >> 32);
    BOOL ok = write ? WriteFile(pf_handle(file), p + done, part, &amount, &ov)
                    : ReadFile(pf_handle(file), p + done, part, &amount, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING)
      ok = GetOverlappedResult(pf_handle(file), &ov, &amount, TRUE);
    if (!ok || amount == 0)
      return false;
    done += amount;
  }
  return true;
}

bool platform_private_file_read_at(struct platform_private_file *f, void *d,
                                   size_t s, uint64_t o) {
  return pf_io(f, d, s, o, false);
}
bool platform_private_file_write_at(struct platform_private_file *f,
                                    const void *d, size_t s, uint64_t o) {
  return pf_io(f, (void *)d, s, o, true);
}
bool platform_private_file_flush(struct platform_private_file *f) {
  return FlushFileBuffers(pf_handle(f)) != 0;
}
bool platform_private_file_mark_executable(struct platform_private_file *f) {
  BY_HANDLE_FILE_INFORMATION info = {0};
  return f && pf_handle(f) != INVALID_HANDLE_VALUE &&
         GetFileInformationByHandle(pf_handle(f), &info) &&
         (info.dwFileAttributes &
          (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
}

bool platform_private_file_replace(struct platform_private_file *f,
                                   const char *staging_path,
                                   const char *destination_path) {
  (void)staging_path;
  wchar_t destination[32768];
  if (!f || pf_handle(f) == INVALID_HANDLE_VALUE ||
      !pf_wide(destination_path, destination) ||
      !platform_private_file_flush(f))
    return false;
  size_t bytes = wcslen(destination) * sizeof(*destination);
  if (bytes > UINT32_MAX - sizeof(FILE_RENAME_INFO))
    return false;
  size_t allocation = sizeof(FILE_RENAME_INFO) + bytes;
  FILE_RENAME_INFO *rename_info =
      zcl_calloc(1, allocation, "private_file_rename_info");
  if (!rename_info)
    return false;
  rename_info->ReplaceIfExists = TRUE;
  rename_info->FileNameLength = (DWORD)bytes;
  memcpy(rename_info->FileName, destination, bytes);
  bool ok = SetFileInformationByHandle(pf_handle(f), FileRenameInfo,
                                       rename_info, (DWORD)allocation) != 0;
  free(rename_info);
  if (ok)
    platform_private_file_close(f);
  return ok;
}

bool platform_private_file_retire(struct platform_private_file *f,
                                  const char *path) {
  (void)path;
  FILE_DISPOSITION_INFO disposition = {.DeleteFile = TRUE};
  if (!SetFileInformationByHandle(pf_handle(f), FileDispositionInfo,
                                  &disposition, sizeof(disposition)))
    return false;
  /* Closing commits deletion of the staging name before the parent barrier. */
  platform_private_file_close(f);
  return true;
}

bool platform_private_file_retire_if_identity(
    struct platform_private_file *f, const char *path,
    const struct platform_private_file_identity *expected) {
  struct platform_private_file_identity actual;
  if (!expected || !platform_private_file_identity(f, &actual) ||
      actual.volume != expected->volume || actual.file != expected->file)
    return false;
  return platform_private_file_retire(f, path);
}

bool platform_private_file_identity(struct platform_private_file *f,
                                    struct platform_private_file_identity *id) {
  BY_HANDLE_FILE_INFORMATION i;
  if (!f || !id || !GetFileInformationByHandle(pf_handle(f), &i))
    return false;
  id->volume = i.dwVolumeSerialNumber;
  id->file = ((uint64_t)i.nFileIndexHigh << 32) | i.nFileIndexLow;
  return true;
}

bool platform_private_path_resolve(const char *path, char *resolved, size_t rs,
                                   char *parent, size_t ps) {
  wchar_t input[32768], full[32768];
  if (!path || !(path[0] && path[1] == ':' &&
                 (path[2] == '\\' || path[2] == '/')))
    return false;
  if (!pf_wide(path, input))
    return false;
  wchar_t *leaf = wcsrchr(input, L'\\');
  wchar_t *slash = wcsrchr(input, L'/');
  if (!leaf || (slash && slash > leaf))
    leaf = slash;
  if (!leaf || !leaf[1] || wcscmp(leaf + 1, L".") == 0 ||
      wcscmp(leaf + 1, L"..") == 0)
    return false;
  wchar_t leaf_copy[32768];
  size_t leaf_length = wcslen(leaf + 1);
  if (leaf_length >= 32768)
    return false;
  if (leaf[leaf_length] == L'.' || leaf[leaf_length] == L' ' ||
      wcspbrk(leaf + 1, L"<>:\"/\\|?*") != NULL)
    return false;
  wchar_t reserved[16];
  size_t stem = wcscspn(leaf + 1, L".");
  if (stem < sizeof(reserved) / sizeof(reserved[0])) {
    for (size_t i = 0; i < stem; ++i)
      reserved[i] = (wchar_t)towupper(leaf[1 + i]);
    reserved[stem] = L'\0';
    if (wcscmp(reserved, L"CON") == 0 || wcscmp(reserved, L"PRN") == 0 ||
        wcscmp(reserved, L"AUX") == 0 || wcscmp(reserved, L"NUL") == 0 ||
        (stem == 4 && (wcsncmp(reserved, L"COM", 3) == 0 ||
                       wcsncmp(reserved, L"LPT", 3) == 0) &&
         reserved[3] >= L'1' && reserved[3] <= L'9'))
      return false;
  }
  wmemcpy(leaf_copy, leaf + 1, leaf_length + 1);
  bool drive_root = (leaf == input + 2 && input[1] == L':') ||
                    (leaf == input + 6 && wcsncmp(input, L"\\\\?\\", 4) == 0 &&
                     input[5] == L':');
  *leaf = L'\0';
  if (drive_root) {
    leaf[0] = L'\\';
    leaf[1] = L'\0';
  }
  HANDLE h = CreateFileW(
      input, FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
      NULL);
  BY_HANDLE_FILE_INFORMATION info;
  if (h == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(h, &info) ||
      !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
      (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    if (h != INVALID_HANDLE_VALUE)
      CloseHandle(h);
    return false;
  }
  DWORD n = GetFinalPathNameByHandleW(h, full, 32768,
                                      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  CloseHandle(h);
  if (!n || n >= 32768)
    return false;
  if (wcsncmp(full, L"\\\\?\\UNC\\", 8) == 0) {
    wchar_t unc[32768] = L"\\\\";
    size_t length = wcslen(full + 8);
    if (length + 3 >= 32768)
      return false;
    wmemcpy(unc + 2, full + 8, length + 1);
    if (!pf_utf8(unc, parent, ps))
      return false;
  } else {
    const wchar_t *canonical =
        wcsncmp(full, L"\\\\?\\", 4) == 0 ? full + 4 : full;
    if (!pf_utf8(canonical, parent, ps))
      return false;
  }
  size_t used = strlen(parent);
  char leaf_utf8[32768];
  if (!pf_utf8(leaf_copy, leaf_utf8, sizeof(leaf_utf8)))
    return false;
  int wrote = snprintf(resolved, rs, "%s\\%s", parent, leaf_utf8);
  return wrote > 0 && (size_t)wrote < rs && used > 0;
}

bool platform_private_path_absent(const char *path) {
  wchar_t w[32768];
  if (!pf_wide(path, w))
    return false;
  DWORD a = GetFileAttributesW(w);
  if (a != INVALID_FILE_ATTRIBUTES)
    return false;
  DWORD error = GetLastError();
  return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

bool platform_private_file_link_no_clobber(
    const char *s, const char *d,
    const struct platform_private_file_identity *sid, bool *same) {
  if (!sid || !same)
    return false;
  wchar_t ws[32768], wd[32768];
  *same = false;
  if (!pf_wide(s, ws) || !pf_wide(d, wd))
    return false;
  HANDLE source =
      CreateFileW(ws, FILE_READ_ATTRIBUTES,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                  OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  BY_HANDLE_FILE_INFORMATION source_info = {0};
  bool source_ok = source != INVALID_HANDLE_VALUE &&
                   GetFileInformationByHandle(source, &source_info) &&
                   (source_info.dwFileAttributes &
                    (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
                   source_info.dwVolumeSerialNumber == sid->volume &&
                   (((uint64_t)source_info.nFileIndexHigh << 32) |
                    source_info.nFileIndexLow) == sid->file;
  if (source != INVALID_HANDLE_VALUE)
    CloseHandle(source);
  if (!source_ok)
    return false;
  bool created = CreateHardLinkW(wd, ws, NULL) != 0;
  DWORD link_error = created ? ERROR_SUCCESS : GetLastError();
  if (!created && link_error != ERROR_ALREADY_EXISTS &&
      link_error != ERROR_FILE_EXISTS)
    return false;
  HANDLE h =
      CreateFileW(wd, FILE_READ_ATTRIBUTES,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                  OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  BY_HANDLE_FILE_INFORMATION info = {0};
  bool ok = GetFileInformationByHandle(h, &info) &&
            (info.dwFileAttributes &
             (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
  struct platform_private_file_identity did = {
      .volume = info.dwVolumeSerialNumber,
      .file = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow};
  bool identity_matches = ok && did.volume == sid->volume &&
                          did.file == sid->file;
  *same = !created && identity_matches;
  if (created && !identity_matches) {
    FILE_DISPOSITION_INFO disposition = {.DeleteFile = TRUE};
    (void)SetFileInformationByHandle(h, FileDispositionInfo, &disposition,
                                     sizeof(disposition));
  }
  CloseHandle(h);
  return identity_matches;
}

bool platform_private_file_unlink_missing_ok(const char *path) {
  wchar_t w[32768];
  if (!pf_wide(path, w))
    return false;
  return DeleteFileW(w) || GetLastError() == ERROR_FILE_NOT_FOUND;
}

bool platform_private_parent_flush(const char *parent) {
  wchar_t w[32768];
  if (!pf_wide(parent, w))
    return false;
  HANDLE h = CreateFileW(
      w, FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
      NULL);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  BY_HANDLE_FILE_INFORMATION info = {0};
  BOOL ok = GetFileInformationByHandle(h, &info) &&
            (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
  CloseHandle(h);
  /* Windows has no supported directory fsync. The hardlink is the recovery
   * record; this barrier revalidates that its canonical parent was not
   * replaced by a reparse point before the database transition. */
  return ok;
}

#else
#include <fcntl.h>
#include <stdatomic.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1u << 0)
#endif
long syscall(long number, ...);
#endif

/* realpath() is POSIX but glibc hides its declaration when a strict C23
 * translation unit selects only _POSIX_C_SOURCE. Keep the platform seam
 * self-contained instead of changing feature macros for every caller. */
char *realpath(const char *restrict path, char *restrict resolved_path);

void platform_private_file_init(struct platform_private_file *f) {
  if (f) {
    f->native = (uintptr_t)-1;
    f->locked = false;
  }
}
static int pf_fd(const struct platform_private_file *f) {
  return (int)f->native;
}
bool platform_private_file_create(const char *p,
                                  struct platform_private_file *f) {
  int fd = open(p, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return false;
  f->native = (uintptr_t)fd;
  return true;
}
bool platform_private_file_open_locked(const char *p,
                                       struct platform_private_file *f) {
  int fd = open(p, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return false;
  if (flock(fd, LOCK_EX | LOCK_NB)) {
    close(fd);
    return false;
  }
  f->native = (uintptr_t)fd;
  f->locked = true;
  return true;
}
bool platform_private_file_open_locked_create(
    const char *p, struct platform_private_file *f) {
  if (platform_private_file_create(p, f)) {
    if (flock(pf_fd(f), LOCK_EX | LOCK_NB) == 0) {
      f->locked = true;
      return true;
    }
    platform_private_file_close(f);
    return false;
  }
  return platform_private_file_open_locked(p, f);
}
/* Waiting exclusive acquisition: the same advisory whole-file flock as the
 * nonblocking pair, without LOCK_NB, retried across signal interruption.  The
 * kernel still releases it if the holder dies. */
static bool pf_lock_wait(struct platform_private_file *f) {
  int rc;
  do {
    rc = flock(pf_fd(f), LOCK_EX);
  } while (rc != 0 && errno == EINTR);
  if (rc != 0)
    return false;
  f->locked = true;
  return true;
}
bool platform_private_file_open_locked_wait(const char *p,
                                            struct platform_private_file *f) {
  int fd = open(p, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return false;
  f->native = (uintptr_t)fd;
  if (!pf_lock_wait(f)) {
    platform_private_file_close(f);
    return false;
  }
  return true;
}
bool platform_private_file_open_locked_create_wait(
    const char *p, struct platform_private_file *f) {
  if (platform_private_file_create(p, f)) {
    if (pf_lock_wait(f))
      return true;
    platform_private_file_close(f);
    return false;
  }
  return platform_private_file_open_locked_wait(p, f);
}
void platform_private_file_close(struct platform_private_file *f) {
  if (f && (int)f->native >= 0) {
    close(pf_fd(f));
    platform_private_file_init(f);
  }
}
bool platform_private_file_size(struct platform_private_file *f, uint64_t *s) {
  struct stat st;
  if (!s || fstat(pf_fd(f), &st) || !S_ISREG(st.st_mode) || st.st_size < 0)
    return false;
  *s = (uint64_t)st.st_size;
  return true;
}
bool platform_private_file_truncate(struct platform_private_file *f,
                                    uint64_t s) {
  return s <= INT64_MAX && !ftruncate(pf_fd(f), (off_t)s);
}
static bool pf_io(struct platform_private_file *f, void *d, size_t s,
                  uint64_t o, bool w) {
  size_t n = 0;
  while (n < s) {
    ssize_t x = w ? pwrite(pf_fd(f), (char *)d + n, s - n, (off_t)(o + n))
                  : pread(pf_fd(f), (char *)d + n, s - n, (off_t)(o + n));
    if (x < 0 && errno == EINTR)
      continue;
    if (x <= 0)
      return false;
    n += (size_t)x;
  }
  return true;
}
bool platform_private_file_read_at(struct platform_private_file *f, void *d,
                                   size_t s, uint64_t o) {
  return pf_io(f, d, s, o, false);
}
bool platform_private_file_write_at(struct platform_private_file *f,
                                    const void *d, size_t s, uint64_t o) {
  return pf_io(f, (void *)d, s, o, true);
}
bool platform_private_file_flush(struct platform_private_file *f) {
  return fsync(pf_fd(f)) == 0;
}
bool platform_private_file_mark_executable(struct platform_private_file *f) {
  return f && fchmod(pf_fd(f), 0755) == 0;
}
bool platform_private_file_replace(struct platform_private_file *f,
                                   const char *staging_path,
                                   const char *destination_path) {
  struct stat held, named;
  if (!f || !staging_path || !destination_path ||
      fstat(pf_fd(f), &held) != 0 || lstat(staging_path, &named) != 0 ||
      !S_ISREG(held.st_mode) || !S_ISREG(named.st_mode) ||
      held.st_dev != named.st_dev || held.st_ino != named.st_ino ||
      !platform_private_file_flush(f) || rename(staging_path, destination_path))
    return false;
  platform_private_file_close(f);
  return true;
}
bool platform_private_file_retire(struct platform_private_file *f,
                                  const char *path) {
  struct stat held, named;
  if (!f || !path || fstat(pf_fd(f), &held) != 0 ||
      lstat(path, &named) != 0 || !S_ISREG(held.st_mode) ||
      !S_ISREG(named.st_mode) || held.st_dev != named.st_dev ||
      held.st_ino != named.st_ino || unlink(path) != 0)
    return false;
  platform_private_file_close(f);
  return true;
}
bool platform_private_file_retire_if_identity(
    struct platform_private_file *f, const char *path,
    const struct platform_private_file_identity *expected) {
  struct platform_private_file_identity actual;
  if (!path || !expected || !platform_private_file_identity(f, &actual) ||
      actual.volume != expected->volume || actual.file != expected->file)
    return false;
#if defined(__linux__) && defined(SYS_renameat2)
  static _Atomic unsigned long long sequence;
  char quarantine[4096];
  unsigned long long value = atomic_fetch_add_explicit(
      &sequence, 1, memory_order_relaxed);
  int n = snprintf(quarantine, sizeof(quarantine), "%s.z23-retire.%ld.%llu",
                   path, (long)getpid(), value);
  if (n <= 0 || (size_t)n >= sizeof(quarantine))
    return false;
  if (syscall(SYS_renameat2, AT_FDCWD, path, AT_FDCWD, quarantine,
              RENAME_NOREPLACE) != 0)
    return false;
  struct stat moved, held;
  bool same = lstat(quarantine, &moved) == 0 && fstat(pf_fd(f), &held) == 0 &&
              S_ISREG(moved.st_mode) && moved.st_dev == held.st_dev &&
              moved.st_ino == held.st_ino;
  if (same)
    return unlink(quarantine) == 0;
  /* A substituted pathname was moved, not deleted. Restore it only without
   * clobbering any concurrently recreated original name. */
  (void)syscall(SYS_renameat2, AT_FDCWD, quarantine, AT_FDCWD, path,
                RENAME_NOREPLACE);
  errno = ESTALE;
  return false;
#else
  /* Generic POSIX fallback without renameat2/RENAME_NOREPLACE. Create a
   * unique hard link to the held inode, prove the quarantined name points to
   * the same file, then remove both names. This gives the same "retire only
   * the exact inode we opened" guarantee as the Linux renameat2 path, without
   * requiring a NOREPLACE syscall. */
  char quarantine[4096];
  static _Atomic unsigned long long sequence;
  unsigned long long value = atomic_fetch_add_explicit(
      &sequence, 1, memory_order_relaxed);
  int n = snprintf(quarantine, sizeof(quarantine), "%s.z23-retire.%d.%llu",
                   path, (int)getpid(), value);
  if (n <= 0 || (size_t)n >= sizeof(quarantine))
    return false;
  if (link(path, quarantine) != 0)
    return false;
  struct stat moved, held;
  bool same = lstat(quarantine, &moved) == 0 &&
              fstat(pf_fd(f), &held) == 0 &&
              S_ISREG(moved.st_mode) &&
              moved.st_dev == held.st_dev &&
              moved.st_ino == held.st_ino;
  if (!same) {
    (void)unlink(quarantine);
    errno = ESTALE;
    return false;
  }
  if (unlink(path) != 0) {
    (void)unlink(quarantine);
    return false;
  }
  return unlink(quarantine) == 0;
#endif
}
bool platform_private_file_identity(struct platform_private_file *f,
                                    struct platform_private_file_identity *i) {
  struct stat st;
  if (!i || fstat(pf_fd(f), &st))
    return false;
  i->volume = (uint64_t)st.st_dev;
  i->file = (uint64_t)st.st_ino;
  return true;
}
bool platform_private_path_resolve(const char *p, char *r, size_t rs,
                                   char *parent, size_t ps) {
  if (!p || p[0] != '/')
    return false;
  const char *s = strrchr(p, '/');
  if (!s || !s[1] || !strcmp(s + 1, ".") || !strcmp(s + 1, ".."))
    return false;
  char in[PATH_MAX], resolved_parent[PATH_MAX];
  size_t n = (size_t)(s - p);
  if (!n)
    n = 1;
  if (n >= sizeof(in))
    return false;
  memcpy(in, p, n);
  in[n] = 0;
  if (!realpath(in, resolved_parent))
    return false;
  size_t pn = strlen(resolved_parent);
  if (pn >= ps)
    return false;
  memcpy(parent, resolved_parent, pn + 1);
  int x = snprintf(r, rs, "%s/%s", !strcmp(parent, "/") ? "" : parent, s + 1);
  return x > 0 && (size_t)x < rs;
}
bool platform_private_path_absent(const char *p) {
  struct stat st;
  return lstat(p, &st) != 0 && (errno == ENOENT || errno == ENOTDIR);
}
bool platform_private_file_link_no_clobber(
    const char *s, const char *d,
    const struct platform_private_file_identity *si, bool *same) {
  if (!s || !d || !si || !same)
    return false;
  *same = false;
  struct stat source;
  if (lstat(s, &source) || !S_ISREG(source.st_mode) ||
      (uint64_t)source.st_dev != si->volume ||
      (uint64_t)source.st_ino != si->file)
    return false;
  bool created = link(s, d) == 0;
  if (!created && errno != EEXIST)
    return false;
  struct stat st;
  if (lstat(d, &st))
    return false;
  bool identity_matches = S_ISREG(st.st_mode) &&
      (uint64_t)st.st_dev == si->volume && (uint64_t)st.st_ino == si->file;
  *same = !created && identity_matches;
  if (created && !identity_matches)
    (void)unlink(d);
  return identity_matches;
}
bool platform_private_file_unlink_missing_ok(const char *p) {
  return unlink(p) == 0 || errno == ENOENT;
}
bool platform_private_parent_flush(const char *p) {
  int fd = open(p, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
  if (fd < 0)
    return false;
  bool ok = fsync(fd) == 0;
  close(fd);
  return ok;
}
#endif
