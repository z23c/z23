/* Native Windows acceptance: executor refuses without mutating caller state. */
#include "services/zcode_benchmark_executor.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    struct zcode_benchmark_execute_request request;
    struct zcode_benchmark_run_out run;
    struct zcode_benchmark_run_out run_before;
    struct zcode_benchmark_execute_out out;
    struct zcode_benchmark_execute_out out_before;
    memset(&request, 0x3c, sizeof(request));
    memset(&run, 0xa5, sizeof(run));
    memset(&out, 0x5a, sizeof(out));
    run_before = run;
    out_before = out;

    struct zcl_result selfcheck =
        zcode_benchmark_executor_sandbox_selfcheck("must-not-open");
    struct zcl_result ran = zcode_benchmark_executor_run(&request, &run);
    struct zcl_result admitted = zcode_benchmark_executor_admit(
        NULL, "must-not-open", &run, true, 1, &out);
    struct zcl_result executed = zcode_benchmark_execute(NULL, &request, &out);
    struct zcl_result verified =
        zcode_benchmark_executor_verify_receipt("must-not-open", "bad-root");
    if (selfcheck.ok || ran.ok || admitted.ok || executed.ok || verified.ok ||
        memcmp(&run, &run_before, sizeof(run)) != 0 ||
        memcmp(&out, &out_before, sizeof(out)) != 0)
        return 1;

    puts("zcode_benchmark_executor_refusal_acceptance: PASS");
    return 0;
}
