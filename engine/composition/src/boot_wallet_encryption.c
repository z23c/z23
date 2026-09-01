/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Boot-only wallet envelope migration and fail-loud reporting. */

#include "config/boot_internal.h"
#include "config/boot_refusal_reports.h"
#include "event/event.h"
#include "wallet/wallet_sqlite.h"

#include <stdlib.h>

void boot_wallet_migrate_envelopes_or_exit(
    const char *datadir, struct wallet_sqlite *wallet_db,
    struct wallet *wallet)
{
    /* The loader has already paid each legacy WKS1 KDF and proved the disk
     * row count equals the in-memory key count. Rewrite those loaded keys
     * under one wrapped DEK before the residual scrub sees the database. */
    struct zcl_result migration =
        wallet_sqlite_migrate_transparent_keys_r(wallet_db, wallet);
    if (migration.ok)
        return;
    boot_report_wallet_scrub_failed(datadir, &migration);
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "wallet_key_envelope_migration_failed code=%d",
                migration.code);
    exit(1);
}
