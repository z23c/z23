/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * seed_tape — deterministic recording/replay primitive (Phase 6a).
 *
 * The seed tape is the foundation of "every bug becomes a 64-bit
 * seed". A tape owns:
 *
 *   - A deterministic RNG (xoshiro256++) seeded from a single uint64,
 *     hooked into `platform_rng_u64()` via the install-hook API.
 *   - A simulated wall-clock + monotonic clock, hooked into the
 *     `platform_clock_*` install-hook.
 *   - An ordered log of "actions": clock advances and injected
 *     external events (e.g., synthetic peer messages, disk delays).
 *
 * Two modes:
 *   - RECORDING (the default after `seed_tape_open`):
 *       advance() and inject() append to the action log.
 *   - REPLAY (the state of a tape returned by `seed_tape_load`):
 *       advance() and inject() return EROFS; the only mutators are
 *       the implicit RNG draws and `seed_tape_next_event` (which
 *       pops the next inject record).
 *
 * A tape can be serialized to disk with a versioned binary format
 * (magic `ZCLTAPE!`, version byte, flags byte, CRC32C trailer) and
 * loaded back to drive a deterministic replay. Phase 6b adds
 * crash-time capture; Phase 6c adds the simulator harness.
 */

#ifndef ZCL_SIM_SEED_TAPE_H
#define ZCL_SIM_SEED_TAPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct seed_tape seed_tape_t;

/* Open a fresh tape (RECORDING mode) seeded with `seed`. The tape
 * derives:
 *   - A deterministic RNG stream (xoshiro256++ seeded from `seed`).
 *     `seed == 0` is fine — internally the splitmix64 expansion
 *     never produces an all-zero xoshiro state.
 *   - A simulated monotonic clock starting at 0.
 *   - A simulated wall clock starting at `start_wall_unix`. Pass 0
 *     for a deterministic "epoch" run.
 *
 * Returns NULL on allocation failure. Caller owns; release via
 * `seed_tape_close`. */
seed_tape_t *seed_tape_open(uint64_t seed, int64_t start_wall_unix);

/* Free the tape. The caller must `seed_tape_uninstall()` first if
 * the tape was installed; otherwise platform.rng / platform.clock
 * will dereference freed memory on the next call. */
void seed_tape_close(seed_tape_t *tape);

/* Install this tape as the active source for platform.rng +
 * platform.clock. After this:
 *   - Every `platform_rng_u64()` returns the tape's next xoshiro draw.
 *   - Every `platform_clock_now_monotonic_ns()` and
 *     `platform_clock_now_wall_ms()` return the tape's simulated time.
 *
 * Only ONE tape can be installed at a time. Re-installing
 * overwrites the previous (the old tape's pointer is no longer
 * referenced by the platform layer — the caller still owns it).
 *
 * The tape pointer must outlive the install — call `uninstall`
 * before `close`. */
void seed_tape_install(seed_tape_t *tape);

/* Remove the tape; restore the system rng/clock sources. */
void seed_tape_uninstall(void);

/* Advance the tape's simulated monotonic clock by `microseconds`.
 * The simulated wall clock advances by the same delta (in
 * microseconds, ignoring sub-second granularity quirks — wall is
 * a unix epoch second counter).
 *
 * RECORDING mode: appends an `advance` action to the action log.
 * REPLAY mode:    returns -EROFS (tape is read-only).
 *
 * Negative `microseconds` is rejected (monotonic clocks never go
 * backward). Returns 0 on success, negative errno on failure. */
int seed_tape_advance(seed_tape_t *tape, int64_t microseconds);

/* Inject a simulated external event. The tape records the
 * (type, payload) pair so a replay reproduces it in order.
 *
 * Free-form payload — caller defines the type taxonomy. The byte
 * range 0..127 is reserved for cross-cutting categories; 128..255
 * are application-defined. Suggested reserved values:
 *   1 = PEER_MESSAGE     (payload = serialized P2P frame)
 *   2 = BLOCK_RECEIVED   (payload = block hash)
 *   3 = DISK_DELAY       (payload = struct { uint64_t us; })
 *   4 = TIMER_FIRE       (payload = timer id)
 *
 * `len` may be 0 (payload-less event); `payload` may be NULL iff
 * `len == 0`. Maximum payload size is 64 KiB per event.
 *
 * RECORDING mode: appends an `inject` action.
 * REPLAY mode:    returns -EROFS.
 *
 * Returns 0 on success, negative errno on failure. */
int seed_tape_inject(seed_tape_t *tape, uint8_t type,
                     const void *payload, size_t len);

/* ── Counters / introspection ──────────────────────────────────── */

/* Total `platform_rng_u64()` calls served from this tape. */
uint64_t seed_tape_rng_count(const seed_tape_t *tape);

/* Total `seed_tape_advance` records. */
uint64_t seed_tape_clock_advance_count(const seed_tape_t *tape);

/* Total `seed_tape_inject` records. */
uint64_t seed_tape_inject_count(const seed_tape_t *tape);

/* In-memory size of the tape in bytes (header + action records).
 * Useful sizing input for Phase 6b postmortem capsules. */
size_t seed_tape_size_bytes(const seed_tape_t *tape);

/* ── Persistence ───────────────────────────────────────────────── */

/* Serialize the tape to a file. The format is versioned:
 *
 *   magic      : 8 bytes  "ZCLTAPE!"
 *   version    : 1 byte   (currently 1)
 *   flags      : 1 byte   (currently 0)
 *   _reserved  : 6 bytes  (zero)
 *   seed       : 8 bytes  (little-endian uint64)
 *   start_wall : 8 bytes  (little-endian int64, unix seconds)
 *   actions    : 8 bytes  (little-endian uint64, count)
 *   records    : variable — see seed_tape.c
 *   crc32c     : 4 bytes  (over the entire file up to but excluding
 *                          the crc itself; Castagnoli polynomial)
 *
 * Returns 0 on success, negative errno on failure. */
int seed_tape_save(const seed_tape_t *tape, const char *path);

/* Serialize the tape into a caller-owned buffer using the same binary
 * format as `seed_tape_save`.
 *
 * On success, returns 0 and sets `*written_out` to the encoded byte
 * length. If `out_cap` is too small, returns -ENOSPC and sets
 * `*written_out` to the required byte length. This API performs no
 * allocation, making it suitable for the postmortem preallocated
 * scratch-buffer path. */
int seed_tape_save_to_memory(const seed_tape_t *tape,
                             uint8_t *out,
                             size_t out_cap,
                             size_t *written_out);

/* Load a tape from disk. Returns NULL on:
 *   - file missing / unreadable
 *   - magic / version mismatch (format drift)
 *   - CRC32C mismatch (corruption)
 *   - allocation failure
 *
 * The returned tape is in REPLAY mode. Its RNG and clock advance
 * through the recorded values; `seed_tape_advance` /
 * `seed_tape_inject` return -EROFS. */
seed_tape_t *seed_tape_load(const char *path);

/* Load a tape from a memory buffer encoded by `seed_tape_save` or
 * `seed_tape_save_to_memory`. The returned tape is in REPLAY mode. */
seed_tape_t *seed_tape_load_from_memory(const void *data, size_t len);

/* In REPLAY mode, pop the next injected event into the caller's
 * buffer. The simulator dispatches it to whatever handler matches
 * the type.
 *
 * On success returns 0; `*type_out` is set, `*payload_len_out` is
 * the actual payload length, and up to `payload_cap` bytes are
 * written into `payload_out`. If `payload_cap < actual length`,
 * the event is NOT consumed and the function returns -ENOSPC with
 * `*payload_len_out` set to the actual size (so the caller can
 * resize and retry).
 *
 * Returns -ENOENT when no more events are queued. */
int seed_tape_next_event(seed_tape_t *tape,
                         uint8_t *type_out, void *payload_out,
                         size_t payload_cap, size_t *payload_len_out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SEED_TAPE_H */
