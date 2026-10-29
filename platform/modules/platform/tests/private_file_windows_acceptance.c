/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused native acceptance test for the private-file publication seam. */
#include "platform/private_file.h"
#include "platform/positioned_file.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

static int fail(const char *message) {
  fprintf(stderr, "FAIL: %s (win32=%lu)\n", message,
          (unsigned long)GetLastError());
  return 1;
}

static bool join_path(char *out, size_t capacity, const char *root,
                      const char *suffix) {
  size_t root_size = strlen(root), suffix_size = strlen(suffix);
  if (root_size >= capacity || suffix_size >= capacity - root_size)
    return false;
  memcpy(out, root, root_size);
  memcpy(out + root_size, suffix, suffix_size + 1u);
  return true;
}

static bool pf_test_hold_writer(const char *path,
                                struct platform_private_file *held) {
  if (!platform_private_file_open_locked_create_wait(path, held))
    return false;
  struct platform_private_file observer;
  platform_private_file_init(&observer);
  if (platform_private_file_open_observation(path, &observer)) {
    platform_private_file_close(&observer);
    return fail("observation acquired held exclusive writer lock") == 0;
  }
  return true;
}

static bool pf_test_readonly_shared(const char *path) {
  struct platform_private_file observer;
  platform_private_file_init(&observer);
  wchar_t observation_path[4 * MAX_PATH];
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                           observation_path, 4 * MAX_PATH) ||
      !SetFileAttributesW(observation_path, FILE_ATTRIBUTE_READONLY))
    return fail("read-only observation fixture") == 0;
  if (!platform_private_file_open_observation(path, &observer))
    return fail("observation of read-only file refused") == 0;
  struct platform_private_file second_observer;
  platform_private_file_init(&second_observer);
  if (!platform_private_file_open_observation(path, &second_observer))
    return fail("shared observers do not coexist") == 0;
  platform_private_file_close(&second_observer);
  platform_private_file_close(&observer);
  if (!SetFileAttributesW(observation_path, FILE_ATTRIBUTE_NORMAL))
    return fail("restore fixture attributes") == 0;
  return true;
}

struct wait_lock_context {
  const char *path;
  bool acquired;
  DWORD error;
};

static DWORD WINAPI wait_lock_thread(LPVOID opaque) {
  struct wait_lock_context *context = opaque;
  struct platform_private_file file;
  platform_private_file_init(&file);
  context->acquired = platform_private_file_open_locked_wait(context->path,
                                                             &file);
  if (!context->acquired)
    context->error = GetLastError();
  platform_private_file_close(&file);
  if (context->acquired && !pf_test_readonly_shared(context->path)) {
    context->acquired = false;
    context->error = GetLastError();
  }
  return 0;
}

static const char pf_test_payload[] = "position-safe";

struct pf_test_fixture {
  wchar_t directory[MAX_PATH];
  char dir[4 * MAX_PATH];
  char stage[4 * MAX_PATH], destination[4 * MAX_PATH], resolved[4 * MAX_PATH],
      parent[4 * MAX_PATH], conflict[4 * MAX_PATH];
  char invalid[4 * MAX_PATH], wait_lock[4 * MAX_PATH];
  struct platform_private_file file, second;
  struct platform_private_file_identity identity;
  bool same;
};

/* Each scenario helper returns NULL on success or the failure message; main
 * reports it through fail() with no Win32 call in between. */
static const char *pf_test_make_directory(struct pf_test_fixture *fx) {
  wchar_t temp[MAX_PATH];
  if (!GetTempPathW(MAX_PATH, temp) ||
      !GetTempFileNameW(temp, L"zpf", 0, fx->directory) ||
      !DeleteFileW(fx->directory) || !CreateDirectoryW(fx->directory, NULL))
    return "temporary directory";

  if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fx->directory, -1,
                           fx->dir, sizeof(fx->dir), NULL, NULL))
    return "temporary path encoding";
  return NULL;
}

static const char *pf_test_fixture_paths(struct pf_test_fixture *fx) {
  if (!join_path(fx->stage, sizeof(fx->stage), fx->dir, "\\stage.part") ||
      !join_path(fx->destination, sizeof(fx->destination), fx->dir,
                 "\\result.bin") ||
      !join_path(fx->conflict, sizeof(fx->conflict), fx->dir,
                 "\\conflict.bin") ||
      !join_path(fx->wait_lock, sizeof(fx->wait_lock), fx->dir,
                 "\\wait.lock") ||
      !join_path(fx->invalid, sizeof(fx->invalid), fx->dir, "\\file:stream"))
    return "fixture path";
  return NULL;
}

static bool pf_test_resolve_invalid(struct pf_test_fixture *fx) {
  return platform_private_path_resolve(fx->invalid, fx->resolved,
                                       sizeof(fx->resolved), fx->parent,
                                       sizeof(fx->parent));
}

static const char *pf_test_unsafe_paths(struct pf_test_fixture *fx) {
  if (platform_private_path_resolve("relative\\file", fx->resolved,
                                    sizeof(fx->resolved), fx->parent,
                                    sizeof(fx->parent)) ||
      platform_private_path_resolve("\\\\server\\share\\file", fx->resolved,
                                    sizeof(fx->resolved), fx->parent,
                                    sizeof(fx->parent)) ||
      pf_test_resolve_invalid(fx))
    return "unsafe path accepted";
  if (!join_path(fx->invalid, sizeof(fx->invalid), fx->dir, "\\CON.txt"))
    return "reserved path";
  if (pf_test_resolve_invalid(fx))
    return "reserved device leaf accepted";
  if (!join_path(fx->invalid, sizeof(fx->invalid), fx->dir, "\\trailing."))
    return "trailing-dot path";
  if (pf_test_resolve_invalid(fx))
    return "ambiguous trailing-dot leaf accepted";
  if (!platform_private_path_resolve(fx->destination, fx->resolved,
                                     sizeof(fx->resolved), fx->parent,
                                     sizeof(fx->parent)) ||
      strcmp(fx->resolved, fx->destination) != 0)
    return "canonical parent resolution";
  return NULL;
}

static const char *pf_test_create_and_lock(struct pf_test_fixture *fx) {
  platform_private_file_init(&fx->file);
  platform_private_file_init(&fx->second);
  if (!platform_private_file_create(fx->stage, &fx->file))
    return "exclusive create";
  platform_private_file_close(&fx->file);
  struct platform_positioned_file reader;
  platform_positioned_file_init(&reader);
  if (!platform_positioned_file_open(&reader, fx->stage) ||
      !platform_positioned_file_is_private(&reader))
    return "private ACL validation";
  platform_positioned_file_close(&reader);
  if (!platform_positioned_file_open_beneath(&reader, fx->dir, "stage.part") ||
      !platform_positioned_file_is_private(&reader))
    return "private ACL validation through retained parent";
  platform_positioned_file_close(&reader);
  if (platform_private_file_create(fx->stage, &fx->file))
    return "create clobbered existing file";
  if (!platform_private_file_open_locked(fx->stage, &fx->file))
    return "locked open";
  if (platform_private_file_open_locked(fx->stage, &fx->second))
    return "lock admitted second writer";
  return NULL;
}

static const char *pf_test_waiting_lock(struct pf_test_fixture *fx) {
  /* Waiting locks must reach LockFileEx rather than fail in CreateFileW.
   * The contender stays blocked while the first handle owns the range, then
   * succeeds promptly after release. This specifically proves that every
   * access requested by pf_open(), including DELETE, is shared. */
  struct platform_private_file held;
  platform_private_file_init(&held);
  if (!pf_test_hold_writer(fx->wait_lock, &held))
    return "waiting lock create";
  struct wait_lock_context wait_context = {.path = fx->wait_lock};
  HANDLE waiter = CreateThread(NULL, 0, wait_lock_thread, &wait_context, 0,
                               NULL);
  if (!waiter)
    return "waiting lock thread";
  if (WaitForSingleObject(waiter, 100) != WAIT_TIMEOUT) {
    CloseHandle(waiter);
    return "waiting lock did not block";
  }
  platform_private_file_close(&held);
  if (WaitForSingleObject(waiter, 5000) != WAIT_OBJECT_0 ||
      !wait_context.acquired) {
    CloseHandle(waiter);
    SetLastError(wait_context.error);
    return "waiting lock did not acquire after release";
  }
  CloseHandle(waiter);
  return NULL;
}

static const char *pf_test_positional_io(struct pf_test_fixture *fx) {
  const char *payload = pf_test_payload;
  if (!platform_private_file_write_at(&fx->file, payload,
                                      sizeof(pf_test_payload), 17) ||
      !platform_private_file_flush(&fx->file))
    return "positional durable write";
  char observed[sizeof(pf_test_payload)] = {0};
  if (!platform_private_file_read_at(&fx->file, observed, sizeof(observed),
                                     17) ||
      memcmp(payload, observed, sizeof(pf_test_payload)))
    return "positional read";
  uint64_t size = 0;
  if (!platform_private_file_size(&fx->file, &size) ||
      size != 17 + sizeof(pf_test_payload) ||
      !platform_private_file_truncate(&fx->file, sizeof(pf_test_payload)) ||
      !platform_private_file_flush(&fx->file))
    return "size/truncate";
  return NULL;
}

static const char *pf_test_publication(struct pf_test_fixture *fx) {
  if (!platform_private_file_identity(&fx->file, &fx->identity))
    return "identity";
  fx->same = false;
  if (!platform_private_file_link_no_clobber(fx->stage, fx->destination,
                                             &fx->identity, &fx->same) ||
      fx->same)
    return "first no-clobber publication";
  if (!platform_private_file_link_no_clobber(fx->stage, fx->destination,
                                             &fx->identity, &fx->same) ||
      !fx->same)
    return "idempotent publication identity";
  platform_private_file_close(&fx->file);

  if (!platform_private_file_create(fx->conflict, &fx->second))
    return "conflict fixture";
  platform_private_file_close(&fx->second);
  fx->same = false;
  if (platform_private_file_link_no_clobber(fx->stage, fx->conflict,
                                            &fx->identity, &fx->same) ||
      fx->same)
    return "conflicting destination accepted";
  return NULL;
}

static const char *pf_test_replacement(struct pf_test_fixture *fx) {
  /* Replacement stays tied to the verified staging handle and replaces an
   * existing destination atomically. */
  char replacement[4 * MAX_PATH];
  if (!join_path(replacement, sizeof(replacement), fx->dir,
                 "\\replacement.part"))
    return "replacement path";
  if (!platform_private_file_create(replacement, &fx->second) ||
      !platform_private_file_write_at(&fx->second, pf_test_payload,
                                      sizeof(pf_test_payload), 0) ||
      !platform_private_file_replace(&fx->second, replacement, fx->conflict) ||
      !platform_private_path_absent(replacement) ||
      !platform_private_parent_flush(fx->parent))
    return "handle-bound replacement";
  platform_private_file_init(&fx->second);
  char observed[sizeof(pf_test_payload)];
  FILE *installed = fopen(fx->conflict, "rb");
  memset(observed, 0, sizeof(observed));
  if (!installed || fread(observed, 1, sizeof(observed), installed) !=
                        sizeof(observed) ||
      fclose(installed) != 0 ||
      memcmp(observed, pf_test_payload, sizeof(pf_test_payload)))
    return "replacement contents";
  return NULL;
}

static const char *pf_test_durable_cleanup(struct pf_test_fixture *fx) {
  if (!platform_private_file_open_locked(fx->stage, &fx->file) ||
      !platform_private_file_retire(&fx->file, fx->stage) ||
      !platform_private_path_absent(fx->stage) ||
      !platform_private_file_unlink_missing_ok(fx->stage) ||
      !platform_private_parent_flush(fx->parent))
    return "durable cleanup";
  return NULL;
}

static void pf_test_remove_fixture(struct pf_test_fixture *fx) {
  wchar_t wstage[4 * MAX_PATH], wdestination[4 * MAX_PATH],
      wconflict[4 * MAX_PATH];
  MultiByteToWideChar(CP_UTF8, 0, fx->stage, -1, wstage, 4 * MAX_PATH);
  MultiByteToWideChar(CP_UTF8, 0, fx->destination, -1, wdestination,
                      4 * MAX_PATH);
  MultiByteToWideChar(CP_UTF8, 0, fx->conflict, -1, wconflict, 4 * MAX_PATH);
  DeleteFileW(wdestination);
  DeleteFileW(wconflict);
  wchar_t wwait_lock[4 * MAX_PATH];
  MultiByteToWideChar(CP_UTF8, 0, fx->wait_lock, -1, wwait_lock, 4 * MAX_PATH);
  DeleteFileW(wwait_lock);
  RemoveDirectoryW(fx->directory);
}

int main(void) {
  struct pf_test_fixture fx;
  memset(&fx, 0, sizeof(fx));
  const char *failure = pf_test_make_directory(&fx);
  if (!failure)
    failure = pf_test_fixture_paths(&fx);
  if (!failure)
    failure = pf_test_unsafe_paths(&fx);
  if (!failure)
    failure = pf_test_create_and_lock(&fx);
  if (!failure)
    failure = pf_test_waiting_lock(&fx);
  if (!failure)
    failure = pf_test_positional_io(&fx);
  if (!failure)
    failure = pf_test_publication(&fx);
  if (!failure)
    failure = pf_test_replacement(&fx);
  if (!failure)
    failure = pf_test_durable_cleanup(&fx);
  if (failure)
    return fail(failure);
  pf_test_remove_fixture(&fx);
  puts("PASS private_file_acceptance");
  return 0;
}
