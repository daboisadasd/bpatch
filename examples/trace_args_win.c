/*
 * trace_args_win.c — Windows x64 / ARM64
 *
 * Log the first 4 argument registers (MS ABI: rcx/rdx/r8/r9 or x0-x3)
 * to C:\bpatch_trace.txt every time the hook fires.
 *
 * Output format per call:
 *   --- call ---
 *   ARG1(rcx): 0x000000013f001234
 *   ARG2(rdx): 0x0000000000000001
 *   ...
 *
 * Usage:
 *   bpatch target.exe --at 0x140001234 --payload trace_args_win.c
 *   bpatch target.exe --at-export CreateFileW --payload trace_args_win.c
 *
 * Real-world uses:
 *   - Trace what filenames malware opens (hook CreateFileW, dump ARG1 as wide string)
 *   - Trace what registry keys are read  (hook RegOpenKeyExW)
 *   - Trace network targets             (hook connect, dump sockaddr ARG2)
 */

#include "bpatch_rt.h"

#define BP_OUT_PATH "C:\\bpatch_trace.txt"

void payload(void) {
    char sep[] = "--- call ---\r\n";
    dump_str_append(sep, BP_OUT_PATH);
    LOG_REG("ARG1", ARG1, BP_OUT_PATH);
    LOG_REG("ARG2", ARG2, BP_OUT_PATH);
    LOG_REG("ARG3", ARG3, BP_OUT_PATH);
    LOG_REG("ARG4", ARG4, BP_OUT_PATH);
}
