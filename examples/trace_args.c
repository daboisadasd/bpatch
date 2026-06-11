/*
 * trace_args.c — Linux x86-64/aarch64
 *
 * Log the first 6 argument registers (+ return address equiv) to
 * /tmp/bpatch_trace.txt every time the hook fires.
 * Useful for tracing what values a function receives over time.
 *
 * Output format per call:
 *   --- call ---
 *   ARG1: 0x0000000000000042
 *   ARG2: 0x00007ffd12345678
 *   ...
 *   RETVAL_before: 0x... (rax/x0 before function runs — usually garbage)
 *
 * Usage:
 *   bpatch target.elf --at <fn_addr> --payload trace_args.c
 *   tail -f /tmp/bpatch_trace.txt
 */

#include "bpatch_rt.h"

#define BP_OUT_PATH "/tmp/bpatch_trace.txt"

void payload(void) {
    char sep[] = "--- call ---\n";
    dump_str_append(sep, BP_OUT_PATH);
    LOG_REG("ARG1  ", ARG1,   BP_OUT_PATH);
    LOG_REG("ARG2  ", ARG2,   BP_OUT_PATH);
    LOG_REG("ARG3  ", ARG3,   BP_OUT_PATH);
    LOG_REG("ARG4  ", ARG4,   BP_OUT_PATH);
    LOG_REG("ARG5  ", ARG5,   BP_OUT_PATH);
    LOG_REG("ARG6  ", ARG6,   BP_OUT_PATH);
    LOG_REG("RETVAL", RETVAL, BP_OUT_PATH);
}
