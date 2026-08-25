/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Local evidence gates for package and attestation POINTER publishes. */

#include "config/boot_zcode_dht_publish_gate.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "vcs/blob_store.h"
#include "vcs/package_attest.h"
#include "vcs/package_attest_transport.h"
#include "vcs/package_index.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_release.h"
#include "vcs/package_reproduce.h"
#include "vcs/package_store.h"
#include "vcs/package_transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Same ok/code/message refusal shape as rpc_error in boot_zcode_dht_rpc.c so
 * the wire-visible refusal is byte-identical to every other RPC refusal. */
static void gate_error(struct json_value *result, const char *code,
                       const char *message) {
  json_set_object(result);
  json_push_kv_bool(result, "ok", false);
  json_push_kv_str(result, "code", code);
  json_push_kv_str(result, "message", message);
}

/* Bounded whole-file read for the persisted release envelope (allocates
 * *out; caller frees). False when missing, unreadable, empty, or over cap
 * (trailing bytes = not the exact object). */
static bool gate_read_object(const char *path, size_t cap, uint8_t **out,
                             size_t *out_len) {
  *out = NULL;
  *out_len = 0;
  FILE *f = fopen(path, "rb");
  if (!f)
    return false;
  uint8_t *buf = zcl_malloc(cap, "gate_read_object");
  if (!buf) {
    fclose(f);
    return false;
  }
  size_t len = fread(buf, 1, cap, f);
  bool ok = !ferror(f) && feof(f) && len > 0;
  fclose(f);
  if (!ok) {
    free(buf);
    return false;
  }
  *out = buf;
  *out_len = len;
  return true;
}

/* Package-pointer reproduction gate. A zclassic23.package POINTER record
 * claims "this exact package_root is discoverable and fetchable from me".
 * That claim is only honest when this node's own store holds a committed
 * release naming the root AND the store's receipts directory evidences
 * reproduction: >= 2 distinct byte-identical installable build receipts for
 * the exact (package_root, recipe_root) pair the signed release commits
 * (vcs_package_reproduce_scan). Everything else refuses BEFORE a plan token
 * exists, so plan and commit are gated identically. Returns true when the
 * publish may proceed; on refusal the exact named code is in result. */
bool boot_zcode_dht_package_pointer_publish_gate(
    const struct vcs_zcode_dht_publish_spec *spec,
    struct json_value *result) {
  struct vcs_package_store *store = vcs_package_store_global();
  if (!store) {
    gate_error(result, "NO_PACKAGE_STORE",
               "package hosting is disabled on this node; enable -packagehost=1"
               " and install the package with zcode use before publishing its"
               " pointer");
    return false;
  }
  const char *zcode_dir = vcs_package_store_root_dir(store);
  struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
  if (!index) {
    LOG_ERROR("net.zcode_dht", "publish gate: package index build failed for %s",
              zcode_dir);
    gate_error(result, "PACKAGE_INDEX_UNAVAILABLE",
               "the local package index could not be rebuilt from the store");
    return false;
  }
  const struct vcs_package_index_entry *entry =
      vcs_package_index_find_root(index, spec->semantic_root);
  if (!entry) {
    vcs_package_index_free(index);
    gate_error(result, "UNKNOWN_PACKAGE",
               "no locally committed release names this package root");
    return false;
  }
  char path[4400];
  int n = snprintf(path, sizeof(path), "%s/releases/%s", zcode_dir,
                   entry->release_id_hex);
  uint8_t *wire = NULL;
  size_t wire_len = 0;
  struct vcs_package_release release;
  bool read_ok =
      n > 0 && (size_t)n < sizeof(path) &&
      gate_read_object(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &wire,
                       &wire_len) &&
      vcs_package_release_parse(wire, wire_len, &release) ==
          VCS_PACKAGE_RELEASE_OK;
  free(wire);
  vcs_package_index_free(index);
  if (!read_ok) {
    gate_error(result, "RELEASE_UNREADABLE",
               "the persisted release envelope for this package root is missing"
               " or unparseable");
    return false;
  }
  char receipts_dir[4400];
  n = snprintf(receipts_dir, sizeof(receipts_dir), "%s/receipts", zcode_dir);
  struct vcs_reproduce_report report;
  bool scanned = n > 0 && (size_t)n < sizeof(receipts_dir) &&
                 vcs_package_reproduce_scan(receipts_dir, spec->semantic_root,
                                            release.recipe_root, &report);
  if (!scanned || !report.reproduced) {
    gate_error(result, "REPRODUCTION_NOT_EVIDENCED",
               "pointer publication requires reproduction evidence in the local"
               " store: at least 2 distinct byte-identical installable build"
               " receipts for this exact package and recipe root; install the"
               " package with zcode use, run zcode package reproduce, then"
               " republish");
    return false;
  }
  /* The pointer's other half: a stranger who resolves this record fetches
   * transport_root and imports it. That only works when this store holds the
   * root as a complete signed transport carrier — not as the inner package
   * root, and not as one of the derived object sets that ride alongside a
   * carrier. A wrong-shaped root used to pass here and fail only at the
   * consumer with "carrier metadata missing". */
  struct vcs_package_public_verdict verdict;
  enum vcs_package_public_shape shape = vcs_package_public_shape_classify(
      store, spec->transport_root, &verdict);
  char root_hex[65];
  zcl_hex_encode(spec->transport_root, 32, root_hex);
  if (shape != VCS_PACKAGE_PUBLIC_TRANSPORT) {
    LOG_ERROR("net.zcode_dht",
              "publish gate: transport root %s classifies as %s (%s)",
              root_hex, vcs_package_public_shape_string(shape), verdict.rule);
    char message[512];
    (void)snprintf(message, sizeof(message),
                   "the transport root must be a complete signed transport"
                   " carrier held by this node's store; this root classifies"
                   " as '%s' (%s). Publish the carrier root the package's"
                   " transport build produced, not the inner package or a"
                   " derived object root",
                   vcs_package_public_shape_string(shape), verdict.rule);
    gate_error(result, "TRANSPORT_ROOT_NOT_CARRIER", message);
    return false;
  }
  /* Shape is right; prove the binding. import is the consumer's own
   * fetch-time step: it re-derives the whole closure from stored bytes
   * (re-admitting the canonical inner objects, a no-op CAS on the publisher
   * that already holds them) and reports the inner package root it
   * reconstructs — that root must be the one this pointer names, or the
   * record binds a name to somebody else's carrier. */
  struct vcs_package_transport_import import;
  if (vcs_package_transport_import(store, spec->transport_root, &import) !=
          VCS_PACKAGE_TRANSPORT_OK ||
      memcmp(import.package_root, spec->semantic_root, 32) != 0) {
    LOG_ERROR("net.zcode_dht",
              "publish gate: transport root %s does not reconstruct to the"
              " named package root",
              root_hex);
    gate_error(result, "TRANSPORT_ROOT_NOT_BOUND",
               "the transport carrier reconstructs to a different package"
               " root than this pointer names; publish the carrier built"
               " from exactly this package");
    return false;
  }
  return true;
}

/* ── attestation POINTER gate ───────────────────────────────────────────
 *
 * THIS GATE IS HYGIENE, NOT THE SECURITY PROPERTY. READ THAT AGAIN BEFORE
 * BUILDING ANYTHING ON TOP OF IT.
 *
 * All it does is stop THIS node from advertising an attestation pointer it
 * cannot stand behind: bytes it does not hold, bytes that are not a
 * canonical ZCLATT wire, a wire whose embedded signature does not verify,
 * or a wire that attests a DIFFERENT package than the pointer claims. That
 * is worth having — a node should not publish claims it cannot back — but
 * it is a rule this node applies to ITSELF.
 *
 * A hostile node runs its own build. It never calls this function, and no
 * amount of tightening here reaches it. It can publish a pointer in
 * VCS_PACKAGE_ATTEST_DHT_NAMESPACE binding any semantic_root to any
 * transport_root, signed with a perfectly valid record signature, and the
 * DHT will carry it.
 *
 * What actually protects a reader is the RECEIVER-side check:
 * vcs_package_attest_transport_admit() called with a non-NULL
 * expect_package_root — the root the reader was asking about. An
 * attestation whose package_root differs is refused ERR_BINDING and never
 * filed, no matter who published the pointer or how well-formed the record
 * was. `zcode package attest pull` always passes that root; so must any
 * future puller.
 *
 * So: if you are here because you are about to treat an attestation pointer
 * as trustworthy BECAUSE this gate exists, you are wrong, and this comment
 * is here to stop you. The gate makes this node honest. It makes nobody
 * else honest.
 *
 * THIS GATE IS NOT READ-ONLY, AND IT RUNS ON mode=plan TOO. A successful
 * check FILES the attestation at <zcode_dir>/attestations/<id-hex>,
 * because vcs_package_attest_transport_admit() is the single filer and
 * verifying without filing would mean forking the verification logic into
 * a second copy that drifts. The write is idempotent — identical bytes
 * report already_present=true — and in the normal flow it is a no-op,
 * since `zcode package attest offer` filed the attestation before the
 * operator ever published a pointer. It is NOT a no-op when the blob
 * reached the store by some other path, and "usually a no-op" is not
 * "read-only", so a reader expecting plan to be a dry run must be told.
 *
 * Why that is acceptable rather than merely tolerated: publishing a
 * pointer to an attestation IS the node asserting it holds that
 * attestation. Having the bytes filed locally is exactly the state the
 * claim describes, and refusing to file would leave this node advertising
 * evidence it cannot serve out of its own store.
 *
 * PROVIDER records in this namespace are deliberately ungated. A provider
 * claim only says "ask me for these bytes"; a false one fails the fetch and
 * costs a round trip, so a gate would buy nothing. */
bool boot_zcode_dht_attestation_pointer_publish_gate(
    const struct vcs_zcode_dht_publish_spec *spec,
    struct json_value *result) {
  struct vcs_package_store *store = vcs_package_store_global();
  if (!store) {
    gate_error(result, "NO_PACKAGE_STORE",
               "package hosting is disabled on this node; enable -packagehost=1"
               " and run zcode package attest offer to admit the attestation"
               " bytes before publishing its pointer");
    return false;
  }
  const char *zcode_dir = vcs_package_store_root_dir(store);

  /* ONE call carries every rule this gate has: possession of the blob at
   * transport_root, canonical ZCLATT grammar, the embedded secp256k1
   * signature, the recomputed attestation id, and — because
   * expect_package_root is spec->semantic_root and never NULL — that the
   * wire attests exactly the package this pointer names. Re-admitting bytes
   * this node already holds is idempotent by contract, so the gate is free
   * to run on both plan and commit. */
  struct vcs_package_attest_transport_outcome outcome;
  memset(&outcome, 0, sizeof(outcome));
  enum vcs_package_attest_transport_result admitted =
      vcs_package_attest_transport_admit(store, zcode_dir,
                                         spec->transport_root,
                                         spec->semantic_root, &outcome);
  if (admitted == VCS_PACKAGE_ATTEST_TRANSPORT_OK)
    return true;

  /* Name the rule that failed, not merely that something did. The operator
   * reading this has a different next step for every one of these. */
  const char *code = "ATTESTATION_UNPUBLISHABLE";
  const char *why = "the local node cannot stand behind this attestation"
                    " pointer";
  switch (admitted) {
  case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ABSENT:
  case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB:
    code = "ATTESTATION_NOT_HELD";
    why = "this node does not hold the attestation blob at transport_root;"
          " run zcode package attest offer first";
    break;
  case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST:
    code = "ATTESTATION_INVALID";
    why = "the bytes at transport_root are not a canonical ZCLATT wire, or"
          " their embedded verifier signature does not verify";
    break;
  /* No case for VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ID here on purpose: it is
   * structurally unreachable from admit. ERR_ID is only ever produced by
   * att_offer_inner() (package_attest_transport.c), where the id passed in
   * by the caller is compared against the id recomputed from the stored
   * bytes and the two can legitimately disagree. The admit path this gate
   * calls (att_admit_inner()) never takes a caller-supplied id — it derives
   * the id from the wire via att_authenticate() and then files at that same
   * derived id, so there is nothing for it to mismatch against. An
   * unreachable ERR_ID falls into default below (ATTESTATION_UNPUBLISHABLE),
   * same as the other admit-side arms that require fault injection to hit. */
  case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING:
    code = "ATTESTATION_BINDING_MISMATCH";
    why = "the attestation at transport_root attests a DIFFERENT package"
          " root than this pointer's semantic_root";
    break;
  case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_CONFLICT:
    code = "ATTESTATION_STORE_CONFLICT";
    why = "a different or unreadable object already occupies this"
          " attestation id in the local store";
    break;
  default:
    break;
  }
  char message[512];
  (void)snprintf(message, sizeof(message),
                 "%s (rule=%s, blob=%s, attestation=%s)", why,
                 vcs_package_attest_transport_result_string(admitted),
                 vcs_blob_result_string(outcome.blob_error),
                 vcs_package_attest_error_string(outcome.attest_error));
  gate_error(result, code, message);
  return false;
}
