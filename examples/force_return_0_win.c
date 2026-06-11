/*
 * force_return_0_win.c — Windows x64 / ARM64
 *
 * Force the hooked function to always return 0.
 * Useful for bypassing anti-debug, license checks, VM detection, etc.
 *
 * Usage:
 *   bpatch target.exe --at 0x140001234 --payload force_return_0_win.c
 *
 * Example — hook IsDebuggerPresent and make it return 0:
 *   bpatch target.exe --at-export IsDebuggerPresent --payload force_return_0_win.c
 *   (requires target.exe to be the DLL host, not kernel32.dll itself)
 */

#include "bpatch_rt.h"

void payload(void) {
    RETVAL = 0;
    char msg[] = "[bpatch] force_return_0 fired\r\n";
    dump_str_append(msg, "C:\\bpatch_force0.txt");
}
