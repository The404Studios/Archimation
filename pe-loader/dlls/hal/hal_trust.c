/*
 * hal_trust.c - thin trust-gate wrapper used by the HAL family.
 *
 * Centralises the call into trust_gate_check() so each HAL source file
 * has a one-liner.  The underlying trust_gate_check() lives in the
 * loader binary (pe-loader/loader/trust_gate.c) and is exported via
 * -rdynamic; when the loader was started without /dev/trust available
 * the gate is permissive (matches every other DLL in the tree).
 *
 * We *also* honour an env override so QA/test harnesses can deny HAL
 * operations regardless of trust state:
 *   HAL_TRUST_DENY=1   -> all hal_trust_check() return 0 (deny).
 *   HAL_TRUST_AUDIT=1  -> log every check to stderr.
 */

#include <stdio.h>
#include <stdlib.h>

#include "hal_internal.h"

int hal_trust_check(trust_gate_category_t cat,
                    const char *op,
                    const char *arg_summary)
{
    if (getenv("HAL_TRUST_DENY")) {
        if (getenv("HAL_TRUST_AUDIT"))
            fprintf(stderr, "[hal/trust] DENY (env) op=%s\n",
                    op ? op : "?");
        return 0;
    }

    trust_gate_result_t r = trust_gate_check(cat, op, arg_summary);

    if (getenv("HAL_TRUST_AUDIT"))
        fprintf(stderr, "[hal/trust] op=%s cat=%u arg=%s -> %d\n",
                op ? op : "?", (unsigned)cat,
                arg_summary ? arg_summary : "(none)",
                (int)r);

    if (r == TRUST_DENY)
        return 0;
    /* TRUST_ALLOW, TRUST_AUDIT, TRUST_ESCALATE all permit the call;
     * audit/escalate are recorded by trust_gate_check() itself. */
    return 1;
}
