/*
 * patch_retval_win.c — log and override a function's return value
 *
 * Scenario: a license check or anti-debug routine returns 0 on failure.
 * Inject at the site AFTER the function computes rax but BEFORE the caller
 * uses it.  We log what the original value was, then force it to 1 (true/success).
 *
 * Because the epilogue restores registers from the ctx_t struct, writing
 * RETVAL writes back to rax when execution resumes.
 */
#include "bpatch_rt.h"

void payload()
{
    char log[] = "C:\\bpatch_retval.txt";

    /* Log original rax before overwriting it */
    LOG_REG("original_rax", RETVAL, log);

    /* Force success */
    RETVAL = 1;
}
