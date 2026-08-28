/* Native Windows acceptance: CAS refuses without mutating caller state. */
#include "services/consensus_state_publication_cas.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    struct consensus_state_publication_decision_record record;
    struct consensus_state_publication_decision_record before;
    memset(&record, 0xA5, sizeof(record));
    before = record;

    struct zcl_result persisted =
        consensus_state_publication_cas_persist_for_test(-1, "decision", &record);
    if (persisted.ok || memcmp(&record, &before, sizeof(record)) != 0)
        return 1;

    struct zcl_result loaded =
        consensus_state_publication_cas_load(-1, "decision", &record);
    if (loaded.ok || memcmp(&record, &before, sizeof(record)) != 0)
        return 2;

    struct consensus_state_publication_cas_request request;
    memset(&request, 0x5A, sizeof(request));
    struct zcl_result run =
        consensus_state_publication_cas_run(&request, &record);
    if (run.ok || memcmp(&record, &before, sizeof(record)) != 0)
        return 3;

    puts("consensus_state_publication_cas_refusal_acceptance: PASS");
    return 0;
}
