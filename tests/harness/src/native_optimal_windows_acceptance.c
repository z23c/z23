/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native Windows proof: shipped Noise_XXhfs over a real WinSock loopback
 * pair, and the production block, datadir, RPC-cookie, and RPC-client
 * opens on a short path, a drive-absolute path longer than 260 bytes, and
 * a path containing a non-ASCII UTF-8 character. Junctions stay refused
 * where those seams already refuse reparse points. */
#if defined(_WIN32)
#include "controllers/rpc_client.h" // lib-layer-ok:native-optimal-windows
#include "net/noise_transport.h"
#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "platform/socket_compat.h"
#include "platform/windows_path.h"
#include "storage/disk_block_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winioctl.h>

static const uint8_t k_payload[] = {
    'Z', '2', '3', 0x0A, 0x0D, 0x00, 0x7F, 'B'
};
static const unsigned char k_magic[4] = {0x24, 0xe9, 0x27, 0x64};

static int fail(const char *what)
{
    fprintf(stderr, "native_optimal: FAIL %s win32=%lu errno=%d\n",
            what, (unsigned long)GetLastError(), errno);
    return 1;
}

static bool wide_delete_file(const char *utf8)
{
    wchar_t wide[32768];
    if (!platform_windows_wide_path(utf8, wide))
        return false;
    return DeleteFileW(wide) || GetLastError() == ERROR_FILE_NOT_FOUND;
}

static bool wide_remove_dir(const char *utf8)
{
    wchar_t wide[32768];
    if (!platform_windows_wide_path(utf8, wide))
        return false;
    return RemoveDirectoryW(wide) ||
           GetLastError() == ERROR_FILE_NOT_FOUND ||
           GetLastError() == ERROR_PATH_NOT_FOUND;
}

static bool recv_exact(platform_socket_t sock, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        int nread = platform_socket_receive(sock, buf + got, n - got);
        if (nread <= 0)
            return false;
        got += (size_t)nread;
    }
    return true;
}

static bool loopback_pair(platform_socket_t *left, platform_socket_t *right)
{
    *left = PLATFORM_SOCKET_INVALID;
    *right = PLATFORM_SOCKET_INVALID;
    platform_socket_t listener =
        platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    if (listener == PLATFORM_SOCKET_INVALID ||
        platform_socket_parse_address(AF_INET, "127.0.0.1",
                                      &addr.sin_addr) != 1 ||
        platform_socket_bind(listener, (const struct sockaddr *)&addr,
                             sizeof(addr)) != 0 ||
        platform_socket_listen(listener, 1) != 0)
        goto done;
    int addr_len = (int)sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0)
        goto done;
    *left = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (*left == PLATFORM_SOCKET_INVALID ||
        connect(*left, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
        goto done;
    *right = accept(listener, NULL, NULL);
done:
    if (listener != PLATFORM_SOCKET_INVALID)
        platform_socket_close(listener);
    if (*left == PLATFORM_SOCKET_INVALID || *right == PLATFORM_SOCKET_INVALID) {
        if (*left != PLATFORM_SOCKET_INVALID)
            platform_socket_close(*left);
        if (*right != PLATFORM_SOCKET_INVALID)
            platform_socket_close(*right);
        *left = PLATFORM_SOCKET_INVALID;
        *right = PLATFORM_SOCKET_INVALID;
        return false;
    }
    return true;
}

static void close_pair(platform_socket_t left, platform_socket_t right)
{
    if (left != PLATFORM_SOCKET_INVALID)
        platform_socket_close(left);
    if (right != PLATFORM_SOCKET_INVALID)
        platform_socket_close(right);
}

/* Drive one handshake message across the socket into the peer transport.
 * `wire` is consumed (freed) on every path. */
static bool feed_wire(platform_socket_t from, platform_socket_t to,
                      struct noise_transport *peer,
                      uint8_t *wire, size_t wire_len,
                      uint8_t **reply, size_t *reply_len)
{
    bool ok = wire && wire_len > 0 &&
              platform_socket_send_all(from, wire, wire_len);
    uint8_t *got = ok ? malloc(wire_len) : NULL;
    ok = ok && got && recv_exact(to, got, wire_len);
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ok = ok && noise_transport_feed(peer, got, wire_len, reply, reply_len,
                                    &plain, &plain_len) &&
         plain_len == 0;
    free(plain);
    free(got);
    free(wire);
    return ok;
}

static int noise_over_winsock(void)
{
    uint8_t ini_priv[32], res_priv[32];
    if (!rng_fill(ini_priv, sizeof(ini_priv)) ||
        !rng_fill(res_priv, sizeof(res_priv)))
        return fail("identity rng");

    platform_socket_t left = PLATFORM_SOCKET_INVALID;
    platform_socket_t right = PLATFORM_SOCKET_INVALID;
    if (!loopback_pair(&left, &right))
        return fail("winsock loopback");

    uint8_t *msg1 = NULL;
    size_t msg1_len = 0;
    struct noise_transport *ini =
        noise_transport_begin(true, ini_priv, k_magic, &msg1, &msg1_len);
    struct noise_transport *res =
        noise_transport_begin(false, res_priv, k_magic, NULL, NULL);
    size_t expect1 = noise_transport_handshake_msg_len(0);
    size_t expect2 = noise_transport_handshake_msg_len(1);
    size_t expect3 = noise_transport_handshake_msg_len(2);
    uint8_t *msg2 = NULL, *msg3 = NULL, *tail = NULL;
    size_t msg2_len = 0, msg3_len = 0, tail_len = 0;
    bool ok = ini && res && msg1 && msg1_len == expect1 && expect1 > 0 &&
              feed_wire(left, right, res, msg1, msg1_len, &msg2, &msg2_len) &&
              msg2_len == expect2 &&
              feed_wire(right, left, ini, msg2, msg2_len, &msg3, &msg3_len) &&
              msg3_len == expect3 &&
              feed_wire(left, right, res, msg3, msg3_len, &tail, &tail_len) &&
              tail_len == 0;
    msg1 = NULL;
    msg2 = NULL;
    msg3 = NULL;
    free(tail);
    struct noise_transport_snapshot ini_snap, res_snap;
    ok = ok && noise_transport_snapshot(ini, &ini_snap) &&
         noise_transport_snapshot(res, &res_snap) &&
         ini_snap.established && res_snap.established;

    uint8_t *sealed = NULL, *plain = NULL, *extra = NULL;
    size_t sealed_len = 0, plain_len = 0, extra_len = 0;
    ok = ok && noise_transport_write(ini, k_payload, sizeof(k_payload),
                                     &sealed, &sealed_len) &&
         sealed && sealed_len > 0 &&
         platform_socket_send_all(left, sealed, sealed_len);
    uint8_t *ct = ok ? malloc(sealed_len) : NULL;
    ok = ok && ct && recv_exact(right, ct, sealed_len) &&
         noise_transport_feed(res, ct, sealed_len, &extra, &extra_len,
                              &plain, &plain_len) &&
         extra_len == 0 && plain_len == sizeof(k_payload) &&
         memcmp(plain, k_payload, sizeof(k_payload)) == 0;
    free(extra);
    free(plain);
    if (!ok) {
        free(ct);
        free(sealed);
        noise_transport_free(ini);
        noise_transport_free(res);
        close_pair(left, right);
        return fail("winsock noise handshake or payload");
    }

    ct[sealed_len / 2] ^= 0x01u;
    uint8_t *bad_wire = NULL, *bad_plain = NULL;
    size_t bad_wire_len = 0, bad_plain_len = 0;
    bool tampered = noise_transport_feed(res, ct, sealed_len, &bad_wire,
                                         &bad_wire_len, &bad_plain,
                                         &bad_plain_len);
    free(bad_wire);
    free(bad_plain);
    free(ct);
    free(sealed);
    noise_transport_free(ini);
    noise_transport_free(res);
    close_pair(left, right);
    if (tampered)
        return fail("tampered message was accepted");
    puts("native_optimal: tampered message refused");

    if (!loopback_pair(&left, &right))
        return fail("winsock loopback for tampered handshake");
    msg1 = NULL;
    msg1_len = 0;
    msg2 = NULL;
    msg2_len = 0;
    ini = noise_transport_begin(true, ini_priv, k_magic, &msg1, &msg1_len);
    res = noise_transport_begin(false, res_priv, k_magic, NULL, NULL);
    /* Message 0 is the clear `e, e1` tokens. The first authenticated
     * handshake message is the responder's `e, ee, ekem1, s, es`. */
    if (!ini || !res || !msg1 || msg1_len != expect1 ||
        !feed_wire(left, right, res, msg1, msg1_len, &msg2, &msg2_len) ||
        !msg2 || msg2_len != expect2 || expect2 == 0) {
        free(msg2);
        noise_transport_free(ini);
        noise_transport_free(res);
        close_pair(left, right);
        return fail("tampered handshake setup");
    }
    msg1 = NULL;
    msg2[msg2_len - 1] ^= 0x01u;
    uint8_t *damaged_on_wire = malloc(msg2_len);
    bool delivered = damaged_on_wire &&
                     platform_socket_send_all(right, msg2, msg2_len) &&
                     recv_exact(left, damaged_on_wire, msg2_len) &&
                     memcmp(damaged_on_wire, msg2, msg2_len) == 0;
    uint8_t *hs_reply = NULL, *hs_plain = NULL;
    size_t hs_reply_len = 0, hs_plain_len = 0;
    bool accepted = delivered &&
                    noise_transport_feed(ini, damaged_on_wire, msg2_len,
                                         &hs_reply, &hs_reply_len,
                                         &hs_plain, &hs_plain_len);
    free(hs_reply);
    free(hs_plain);
    free(damaged_on_wire);
    free(msg2);
    noise_transport_free(ini);
    noise_transport_free(res);
    close_pair(left, right);
    if (!delivered)
        return fail("tampered handshake delivery");
    if (accepted)
        return fail("tampered handshake was accepted");
    puts("native_optimal: tampered handshake refused");
    return 0;
}

static int round_trip(const char *datadir, const char *label)
{
    if (strlen(datadir) < 3 || !platform_private_directory_ensure(datadir))
        return fail(label);
    disk_block_io_close_cache();
    struct disk_block_pos pos = {.nFile = 0, .nPos = 0};
    FILE *block = open_block_file(datadir, &pos, false);
    if (!block || fwrite(k_payload, 1, sizeof(k_payload), block) !=
                      sizeof(k_payload)) {
        if (block)
            fclose(block);
        return fail("block create");
    }
    fclose(block);
    disk_block_io_close_cache();
    block = open_block_file(datadir, &pos, true);
    uint8_t got[sizeof(k_payload)];
    memset(got, 0, sizeof(got));
    bool block_ok = block &&
                    fread(got, 1, sizeof(got), block) == sizeof(got) &&
                    memcmp(got, k_payload, sizeof(got)) == 0;
    disk_block_io_close_cache();
    if (!block_ok)
        return fail("block round-trip");

    char cookie[4096];
    int cookie_len = snprintf(cookie, sizeof(cookie), "%s/.cookie", datadir);
    if (cookie_len <= 0 || (size_t)cookie_len >= sizeof(cookie))
        return fail("cookie path");
    struct platform_private_file file;
    platform_private_file_init(&file);
    uint8_t cookie_got[sizeof(k_payload)];
    memset(cookie_got, 0, sizeof(cookie_got));
    bool cookie_ok = platform_private_file_create(cookie, &file) &&
                     platform_private_file_write_at(&file, k_payload,
                                                    sizeof(k_payload), 0) &&
                     platform_private_file_read_at(&file, cookie_got,
                                                   sizeof(cookie_got), 0) &&
                     memcmp(cookie_got, k_payload, sizeof(k_payload)) == 0;
    platform_private_file_close(&file);
    if (!cookie_ok)
        return fail("rpc-cookie round-trip");

    uint8_t client_got[sizeof(k_payload) + 4];
    size_t client_n = 0;
    memset(client_got, 0, sizeof(client_got));
    if (!node_rpc_client_read_file(cookie, client_got, sizeof(client_got),
                                   &client_n) ||
        client_n != sizeof(k_payload) ||
        memcmp(client_got, k_payload, sizeof(k_payload)) != 0)
        return fail("rpc-client round-trip");
    char *answer = node_rpc_call_at_deadline(datadir, 1, "getinfo", "[]",
                                              200, 500);
    bool opened = answer && strstr(answer, "cannot read RPC auth cookie") == NULL &&
                  strstr(answer, "cannot connect") != NULL;
    free(answer);
    if (!opened)
        return fail("rpc-client cookie open");

    char blocks[4096], blk[4096];
    snprintf(blocks, sizeof(blocks), "%s/blocks", datadir);
    snprintf(blk, sizeof(blk), "%s/blocks/blk00000.dat", datadir);
    wide_delete_file(cookie);
    wide_delete_file(blk);
    wide_remove_dir(blocks);
    wide_remove_dir(datadir);
    printf("native_optimal: %s block/datadir/cookie/rpc-client PASS\n", label);
    return 0;
}

static bool make_junction(const char *link_utf8, const char *target_utf8)
{
    wchar_t link[32768], plain[32768], absolute[32768];
    if (!platform_windows_wide_path(link_utf8, link) ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, target_utf8, -1,
                            plain, 32768) <= 0 ||
        !GetFullPathNameW(plain, 32768, absolute, NULL) ||
        !CreateDirectoryW(link, NULL))
        return false;
    HANDLE handle = CreateFileW(
        link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    struct {
        DWORD tag;
        USHORT length, reserved;
        USHORT substitute_offset, substitute_length, print_offset, print_length;
        WCHAR path[2048];
    } data = {.tag = IO_REPARSE_TAG_MOUNT_POINT};
    size_t count = wcslen(absolute);
    bool ok = count < 900u;
    if (ok) {
        memcpy(data.path, L"\\??\\", 4 * sizeof(WCHAR));
        memcpy(data.path + 4, absolute, (count + 1u) * sizeof(WCHAR));
        data.substitute_length = (USHORT)((count + 4u) * sizeof(WCHAR));
        data.print_offset = (USHORT)(data.substitute_length + sizeof(WCHAR));
        data.print_length = (USHORT)(count * sizeof(WCHAR));
        memcpy((BYTE *)data.path + data.print_offset, absolute,
               (count + 1u) * sizeof(WCHAR));
        data.length = (USHORT)(8u + data.print_offset + data.print_length +
                               sizeof(WCHAR));
        DWORD transferred = 0;
        ok = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, &data,
                             (DWORD)data.length + 8u, NULL, 0, &transferred,
                             NULL) != 0;
    }
    CloseHandle(handle);
    return ok;
}

static int junction_refusal(const char *root)
{
    char target[4096], link[4096];
    snprintf(target, sizeof(target), "%s\\junction-target", root);
    snprintf(link, sizeof(link), "%s\\junction-link", root);
    if (!platform_private_directory_ensure(target) ||
        !make_junction(link, target))
        return fail("junction fixture");
    bool refused = !platform_private_directory_ensure(link) &&
                   !platform_directory_ensure(link, 0755);
    struct platform_private_file file;
    platform_private_file_init(&file);
    refused = refused && !platform_private_file_create(link, &file);
    platform_private_file_close(&file);
    wchar_t link_wide[32768];
    if (platform_windows_wide_path(link, link_wide))
        RemoveDirectoryW(link_wide);
    wide_remove_dir(target);
    if (!refused)
        return fail("junction was accepted");
    puts("native_optimal: junction refused");
    return 0;
}

static int temp_root(char *out, size_t out_size)
{
    wchar_t temp[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, temp);
    if (n == 0 || n >= MAX_PATH)
        return fail("temp path");
    char utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, temp, -1, utf8,
                             (int)sizeof(utf8), NULL, NULL))
        return fail("temp utf8");
    size_t len = strlen(utf8);
    while (len > 0 && (utf8[len - 1] == '\\' || utf8[len - 1] == '/'))
        utf8[--len] = '\0';
    unsigned tick = GetTickCount();
    int wrote = snprintf(out, out_size, "%s\\z23nat%u", utf8, tick);
    if (wrote <= 0 || (size_t)wrote >= out_size)
        return fail("root path");
    if (!platform_private_directory_ensure(out))
        return fail("root directory");
    return 0;
}

/* An existing directory addressed with ".." must survive the \\?\ prefix.
 * CreateDirectoryW on the extended form of an uncollapsed ".." returns
 * ERROR_INVALID_NAME; the shipped ensure calls then report failure for a
 * directory that is already there. */
static int dotdot_directory_ensure(const char *root)
{
    const char *slash = strrchr(root, '\\');
    if (!slash || slash[1] == '\0')
        return fail("dotdot root shape");
    char via[2048];
    int wrote = snprintf(via, sizeof(via), "%s\\..\\%s", root, slash + 1);
    if (wrote <= 0 || (size_t)wrote >= sizeof(via))
        return fail("dotdot path");
    if (!platform_directory_ensure(via, 0755))
        return fail("dotdot directory ensure");
    if (!platform_private_directory_ensure(via))
        return fail("dotdot private directory ensure");
    printf("native_optimal: dotdot directory ensure PASS\n");
    return 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    int noise = noise_over_winsock();
    if (noise != 0)
        return noise;

    char root[1024];
    int rooted = temp_root(root, sizeof(root));
    if (rooted != 0)
        return rooted;

    char short_path[2048];
    char long_path[2048];
    char utf8_path[2048];
    snprintf(short_path, sizeof(short_path), "%s\\short", root);
    snprintf(utf8_path, sizeof(utf8_path), "%s\\z23-\xE6\xB5\x8B", root);
    int long_wrote = snprintf(long_path, sizeof(long_path), "%s\\", root);
    if (long_wrote <= 0 || (size_t)long_wrote >= sizeof(long_path))
        return fail("long prefix");
    size_t leaf = strlen(long_path);
    while (strlen(long_path) <= 260) {
        if (leaf + 1 >= sizeof(long_path))
            return fail("long path overflow");
        long_path[leaf++] = 'a';
        long_path[leaf] = '\0';
    }
    if (strlen(long_path) <= 260 || leaf - (size_t)long_wrote > 255)
        return fail("long path shape");

    int rc = round_trip(short_path, "short ascii");
    if (rc == 0)
        rc = round_trip(long_path, "long path");
    if (rc == 0)
        rc = round_trip(utf8_path, "utf-8");
    if (rc == 0)
        rc = junction_refusal(root);
    if (rc == 0)
        rc = dotdot_directory_ensure(root);
    wide_remove_dir(root);
    if (rc != 0)
        return rc;
    puts("native_optimal: PASS");
    return 0;
}
#else
typedef int native_optimal_windows_acceptance_not_built;
#endif
