/*
 * force_return_0.c — Linux x86-64/aarch64
 *
 * Force the hooked function to always return 0 (success/false/NULL).
 * The original function body still runs — this only overrides the return value.
 *
 * Useful for bypassing:
 *   - Anti-debug checks that return non-zero on detection
 *   - License validation functions
 *   - "IsRunningInVM" / "IsDebuggerPresent"-style checks
 *
 * Usage:
 *   bpatch target.elf --at <check_fn_addr> --payload force_return_0.c
 *
 * To skip the function body entirely, hook the ENTRY of the function and set
 * RETVAL = 0 then use a separate mechanism to skip (advanced).
 * For the common case, hooking the RET site and overwriting rax works better.
 */

#include "bpatch_rt.h"

void payload(void) {
    RETVAL = 0;
    /* Log when we fire (optional — comment out for silent operation) */
    char msg[] = "[bpatch] force_return_0 fired\n";
    dump_str_append(msg, "/tmp/bpatch_force0.txt");
}
