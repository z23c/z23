/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — READ WHAT THE ARTIFACT CLAIMS, BEFORE IT IS MAPPED.
 *
 * ── THE ORDERING DEFECT THIS EXISTS TO CLOSE ───────────────────────────────
 * hotswap_activate.c learns a module's identity — its ABI stamp, its
 * consensus seal root, its leaf table — with dlsym(), which can only run
 * AFTER dlopen(). By then the artifact is already mapped into the resident
 * node's address space and the dynamic linker has ALREADY executed, in order:
 *
 *     1. every DT_NEEDED library's own initialisers (a foreign NEEDED entry
 *        drags in a whole second artifact nobody inspected),
 *     2. the object's DT_PREINIT_ARRAY (executables only under glibc, but
 *        present in a DSO is a fact worth knowing),
 *     3. DT_INIT,
 *     4. every function pointer in DT_INIT_ARRAY.
 *
 * All four run before hotswap_module_admit() has looked at a single field. A
 * module that fails admission has, at that point, already run arbitrary code
 * inside the node. Refusing it afterwards refuses nothing that matters — and
 * the loader deliberately never dlcloses, so even the mapping stays.
 *
 * The repository lints its OWN sources for __attribute__((constructor)). That
 * lint is worth exactly as much as the assumption that every module was built
 * from a source this repository linted — which is the assumption module
 * PACKAGING exists to break. A .so handed to us from elsewhere never passed
 * that lint and never will.
 *
 * This probe inverts the order: it reads the file's ELF structure from a
 * descriptor, extracts what the file CLAIMS about itself, and reports the
 * pre-admission code-execution surface as raw counts — with zero code from
 * the artifact executed, and without the artifact ever being mapped.
 *
 * ── WHAT THIS PROVES, AND WHAT IT DOES NOT ─────────────────────────────────
 * PROVES: the values reported here are the values recorded in the file's own
 * ELF structures at the offsets the dynamic linker itself will read them from
 * — the PT_DYNAMIC segment for the initialiser arrays and DT_NEEDED, and
 * DT_SYMTAB/DT_STRTAB for the identity symbols. It is a precise read, not a
 * scan for plausible-looking bytes.
 *
 * DOES NOT PROVE: that the code behind those structures is safe. A module can
 * carry the clean baseline in every field here and still be entirely
 * malicious — every byte of that malice simply lives in a leaf handler
 * instead of a constructor. This probe narrows WHEN unadmitted code can run,
 * from "before any check" to "only after admission lets a leaf be called". It
 * does not decide whether the code should run at all. It also does not verify
 * a signature, a provenance chain, or an allowlist row; those are separate
 * lanes.
 *
 * DOES NOT PROVE: that a probe-clean file will actually load. This reads the
 * file; it does not simulate the dynamic linker.
 *
 * ── THIS PROBE MAKES NO POLICY DECISION ────────────────────────────────────
 * It reports COUNTS. It never returns "safe" or "unsafe". The caller writes
 * the policy, and the counts below exist so the caller can write a correct
 * one instead of a superstitious one.
 *
 * ── ⛔ THE BASELINE TRAP: A CLEAN MODULE HAS init_array_entries == 1 ────────
 * `.init_array` is NOT empty on a clean module and never has been. Every
 * module this repository builds carries exactly ONE entry: the C runtime's
 * own `frame_dummy`, emitted by crtbegin for unwind-table registration. It is
 * not ours, we cannot remove it, and it is present in every artifact the
 * toolchain has ever produced here.
 *
 * VERIFIED, not assumed — this probe was run over EVERY artifact in
 * build/hotswap/ at the time this file was written: 93 .so files spanning 24
 * distinct source translation units, every one of them probing clean.
 * DT_INIT_ARRAYSZ == 8 bytes == exactly 1 entry in 93 of 93, with that entry
 * pointing at `__frame_dummy_init_array_entry` / `frame_dummy`.
 *
 * The rest of the measured baseline, same 93 artifacts, 100% agreement
 * unless noted:
 *
 *     init_array_entries      1     (crt frame_dummy — ⛔ NOT 0)
 *     fini_array_entries      1     (its crt counterpart — ⛔ NOT 0)
 *     preinit_array_entries   0
 *     has_dt_init             true  (⛔ the crt _init stub — NOT a signal)
 *     has_dt_fini             true
 *     needed_count            1, and needed[0] == "libc.so.6"
 *     has_runpath             false
 *     abi_version             2 (ZCL_HOTSWAP_MODULE_ABI_V2) in 92 of 93; the
 *                             one exception is a hotfork capsule
 *                             (build/hotswap/gen-*.so) which exports
 *                             zcl_hotswap_manifest_v2 instead of
 *                             zcl_hotswap_module and correctly reports
 *                             abi_version_present == false
 *     core_seal_root          present in 26 of 93 — exactly the 26 artifacts
 *                             that carry a .so.manifest; the other 67 are
 *                             pre-pin builds and report "" (see the field
 *                             comment: absence is reported, not refused)
 *     undefined_symbol_count  18 .. 94
 *
 * Therefore:
 *
 *     ⛔ "has constructors"  is NOT  init_array_entries > 0
 *     ✅ "has constructors"  IS      init_array_entries > ZCL_HOTSWAP_ELF_PROBE_CLEAN_INIT_ARRAY_ENTRIES
 *
 * A policy written against `> 0` refuses every clean module and will be
 * "fixed" by deleting the check. A policy written against the baseline
 * constant refuses exactly the artifacts that added something.
 *
 * The same trap applies to has_dt_init: DT_INIT is present in EVERY clean
 * module (it points at the crt `_init` stub, address 0x1000 in each artifact
 * measured). `has_dt_init == true` is the NORMAL state and means nothing on
 * its own. It is reported because DT_INIT is a real pre-admission entry point
 * and a policy that pins the initialiser arrays while ignoring DT_INIT has
 * left a door open — but it must be judged against what the module's own
 * toolchain emits, not against zero.
 *
 * ── WHY DT_NEEDED IS REPORTED HERE ─────────────────────────────────────────
 * A probe that counted only this object's own initialisers would miss the
 * largest constructor vector there is: DT_NEEDED. ld.so loads each named
 * library and runs ITS initialisers before this object's, so one forged
 * NEEDED entry executes a whole second artifact that this probe was never
 * shown. Reporting the names lets a policy pin the dependency set, which is
 * the only way the initialiser counts above mean anything.
 *
 * ── READ-ONLY, fd-ONLY, NO CODE FROM THE ARTIFACT RUNS ─────────────────────
 * No dlopen, no dlsym, no fork, no exec, no nm/readelf/objdump, no path
 * re-open. Everything is read from the caller's descriptor, matching
 * hotswap_artifact_sha3_fd()'s fd discipline so the bytes probed are the
 * bytes of the inode the caller already holds (see hotswap_artifact_digest.h
 * for what that pin does and does not buy).
 *
 * ── HOSTILE-INPUT DISCIPLINE ───────────────────────────────────────────────
 * The input is assumed to be adversarial in every field. A bug here would be
 * worse than the ordering defect it closes, so:
 *   - every offset+length is overflow-checked and bounds-checked against the
 *     actual byte count read from the descriptor, before any dereference;
 *   - no attacker-controlled count is ever used as an allocation size; the
 *     only allocation is the file image itself, hard-capped at
 *     ZCL_HOTSWAP_ELF_PROBE_MAX_FILE_BYTES;
 *   - every enumeration is capped (phdrs, section headers, dynamic entries,
 *     dynamic symbols) and a file exceeding a cap is REFUSED, not truncated;
 *   - a string read out of the dynamic string table must terminate inside
 *     DT_STRSZ; a missing NUL is a refusal, never a run-on read;
 *   - anything not ELF64 / little-endian / ET_DYN / EM_X86_64 is refused on
 *     the header, before any table is walked.
 *
 * FAIL CLOSED, ALWAYS. Every refusal path returns false with a specific
 * reason in `err`. A malformed file NEVER comes back as `true` with zeroed
 * facts — "I could not read it" and "it claims nothing" are different
 * answers and conflating them is how a hostile artifact gets admitted. The
 * probe is deliberately stricter than the dynamic linker: several shapes a
 * linker would tolerate (no section header table, extended section
 * numbering, no symbol hash table) are refused here, because a module we
 * cannot fully describe is a module we should not mount.
 *
 * ── DELIBERATE STRICTNESS: THE TWO READERS MUST AGREE ──────────────────────
 * Facts are taken from PT_DYNAMIC, because that is what ld.so reads. But the
 * section header table is ALSO validated, and where the two describe the same
 * region (.init_array / .preinit_array sizes, and PT_DYNAMIC's own location)
 * they are required to agree. That is not redundancy for its own sake: every
 * human tool and every packaging script in this tree (tools/dev/
 * hotswap-package.sh, nm, readelf, gdb) reads section headers, while the
 * loader reads only the dynamic segment. A file where those disagree is a
 * file that describes itself one way to the auditor and another way to the
 * linker, and that is precisely the deception this probe exists to catch.
 */
#ifndef ZCL_HOTSWAP_ELF_PROBE_H
#define ZCL_HOTSWAP_ELF_PROBE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Hard caps. Exceeding any of these is a REFUSAL, never a truncation. ──
 *
 * These bound work and memory against a hostile header field. They are set
 * far above anything this repository produces (largest artifact measured:
 * ~390 KB, 10 program headers, 38 section headers, 27 dynamic entries, 46
 * dynamic symbols) so a legitimate module can never trip one, and far below
 * anything that could exhaust the node. */

/* Whole-image allocation ceiling. The image is read into one contiguous
 * buffer so that every bounds check is against a single known length; this
 * cap is what keeps that allocation from being attacker-sized. */
#define ZCL_HOTSWAP_ELF_PROBE_MAX_FILE_BYTES ((uint64_t)32u << 20) /* 32 MiB */

#define ZCL_HOTSWAP_ELF_PROBE_MAX_PHNUM      512u
#define ZCL_HOTSWAP_ELF_PROBE_MAX_SHNUM      4096u
#define ZCL_HOTSWAP_ELF_PROBE_MAX_DYNAMIC    4096u
#define ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS    65536u

/* DT_NEEDED names recorded verbatim. More than this is not an error — the
 * count is still exact and needed_truncated is set — because the count alone
 * is enough for a policy to refuse, and a fixed cap keeps this struct
 * stack-safe. */
#define ZCL_HOTSWAP_ELF_PROBE_MAX_NEEDED     8u
#define ZCL_HOTSWAP_ELF_PROBE_NEEDED_NAME_CAP 64u

/* ⛔ THE CLEAN BASELINE. See the header comment: this is 1, not 0, because
 * crtbegin's `frame_dummy` occupies the single entry in every artifact this
 * toolchain builds. A constructor-detection policy compares AGAINST THIS,
 * never against zero. */
#define ZCL_HOTSWAP_ELF_PROBE_CLEAN_INIT_ARRAY_ENTRIES ((size_t)1)

/* Recommended minimum for `err`; every message this probe emits fits. */
#define ZCL_HOTSWAP_ELF_PROBE_ERR_CAP 256u

/* Everything the file claims about itself, read without mapping it.
 *
 * Populated only on a `true` return. On `false` the struct is zeroed and
 * carries no partial facts — a partially-parsed hostile file must not leave
 * half-believable values behind for a caller who forgot to check the return
 * value. */
struct hotswap_elf_facts {
    /* ── identity claims (the values dlsym would have returned) ────────── */

    /* Contents of the exported ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL
     * (`zcl_hotswap_module_core_seal_root`) string: exactly 64 lowercase hex
     * characters plus NUL. "" (empty) if the symbol is ABSENT from the
     * dynamic symbol table.
     *
     * Absence is reported, not refused: a pre-pin artifact is a legitimate
     * thing to be handed and refusing it is the CALLER's policy call (and
     * hotswap_activate.c already refuses one). But a symbol that is PRESENT
     * and does not hold 64 lowercase hex + NUL is a malformed claim and
     * refuses the whole probe — reporting a garbage pin that a caller would
     * then string-compare is worse than reporting nothing. */
    char     core_seal_root[65];

    /* First member of the exported `zcl_hotswap_module` struct
     * (ZCL_HOTSWAP_MODULE_SYMBOL). C guarantees the first named member sits
     * at offset 0 with no leading padding, which is the one layout fact that
     * holds regardless of compiler or alignment — so this is a precise read
     * of that field, not a hand-rolled struct parser. It breaks in lockstep
     * with hotswap_module.h if a future ABI stops leading with abi_version,
     * exactly as tools/dev/hotswap-package.sh does.
     *
     * 0 and abi_version_present == false if the symbol is absent. Note that
     * 0 is also a legal-looking value for a hostile file to stamp, which is
     * why presence is a separate flag rather than inferred from a sentinel. */
    uint32_t abi_version;
    bool     abi_version_present;

    /* ── pre-admission code-execution surface ──────────────────────────── */

    /* DT_INIT_ARRAYSZ / sizeof(void *). ⛔ CLEAN BASELINE IS 1, NOT 0 — see
     * ZCL_HOTSWAP_ELF_PROBE_CLEAN_INIT_ARRAY_ENTRIES and the header comment.
     * Raw count, no interpretation. */
    size_t   init_array_entries;

    /* DT_PREINIT_ARRAYSZ / sizeof(void *). Clean baseline 0. glibc runs a
     * preinit array only for the main executable and ignores it in a DSO, so
     * a nonzero value here is not itself an execution path under glibc — it
     * is an anomaly (no toolchain in this tree emits one) and a different
     * loader may honour it. Reported for the policy to judge. */
    size_t   preinit_array_entries;

    /* DT_FINI_ARRAYSZ / sizeof(void *), and DT_FINI presence. These run at
     * process teardown, not at load, so they are NOT part of the ordering
     * defect above — but they are still unadmitted code registered inside the
     * node's address space by an artifact the loader never dlcloses. Clean
     * baseline: fini_array_entries == 1, has_dt_fini == true (the crt pair of
     * the init entries). Same trap, same rule: compare against the baseline,
     * not against zero. */
    size_t   fini_array_entries;
    bool     has_dt_fini;

    /* DT_INIT present. ⛔ TRUE ON EVERY CLEAN MODULE (the crt `_init` stub).
     * Not a signal on its own. */
    bool     has_dt_init;

    /* DT_NEEDED entries. Clean baseline: needed_count == 1, needed[0] ==
     * "libc.so.6". Names are NUL-terminated and truncated to fit; a name too
     * long to fit is still counted. needed_truncated is set when there were
     * more than ZCL_HOTSWAP_ELF_PROBE_MAX_NEEDED entries (needed_count stays
     * exact) or when any recorded name was shortened. */
    size_t   needed_count;
    char     needed[ZCL_HOTSWAP_ELF_PROBE_MAX_NEEDED][ZCL_HOTSWAP_ELF_PROBE_NEEDED_NAME_CAP];
    bool     needed_truncated;

    /* DT_RPATH or DT_RUNPATH present. Clean baseline false. A runpath changes
     * WHICH library each DT_NEEDED name resolves to, so it can redirect even
     * a baseline-looking dependency set to attacker-chosen code. */
    bool     has_runpath;

    /* ── shape ─────────────────────────────────────────────────────────── */

    /* Total entries in the dynamic symbol table, derived from DT_HASH's
     * nchain when present and otherwise from a DT_GNU_HASH bucket/chain walk
     * — i.e. from the same structures the linker uses to size that table,
     * never from a section header. */
    size_t   dynamic_symbol_count;

    /* Dynamic symbols with st_shndx == SHN_UNDEF and a non-empty name: the
     * symbols this module imports from the host at load time. Under the
     * shipped -Wl,-z,now link every one of these must resolve at dlopen or
     * the load fails, so this is the module's demanded surface against the
     * resident. Clean modules measured here sit in the 30-40 range. */
    size_t   undefined_symbol_count;

    /* Bytes actually read from the descriptor. */
    uint64_t file_size;
};

/* Probe the ELF image on descriptor `fd` without mapping or executing it.
 *
 * Reads the whole file from offset 0 regardless of the descriptor's current
 * position, and leaves the descriptor's offset at 0 on success (matching
 * hotswap_artifact_sha3_fd, so the two compose over one descriptor). Does not
 * close fd; ownership stays with the caller.
 *
 * Returns true only when the file is a well-formed ELF64 little-endian ET_DYN
 * x86-64 shared object whose structures are entirely self-consistent and
 * in-bounds, in which case *out holds the facts above.
 *
 * Returns false on ANY refusal — bad descriptor, non-regular file, empty
 * file, oversize file, wrong ELF class/endianness/type/machine, any offset or
 * size out of bounds or overflowing, any cap exceeded, any internal
 * disagreement between the section table and the dynamic segment, an
 * unterminated dynamic string, or a malformed identity symbol. On false, *out
 * is zeroed and `err` (when non-NULL and err_cap > 0) holds a NUL-terminated
 * one-line reason naming the specific structure that failed. `err` is set to
 * "" on success.
 *
 * NEVER returns true for a file it could not fully parse. Callers must treat
 * false as "refuse this artifact", not as "assume the defaults". */
bool hotswap_elf_probe_fd(int fd, struct hotswap_elf_facts *out,
                          char *err, size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_HOTSWAP_ELF_PROBE_H */
